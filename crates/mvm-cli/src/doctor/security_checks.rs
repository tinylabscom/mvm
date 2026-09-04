//! Security posture checks folded in from the old `mvmctl security` verb:
//! audit log, host FDE, data-dir/socket/snapshot modes, and signing.

use anyhow::Result;

use super::Check;
use super::builder::dev_vm_socket_path;
use mvm_core::platform::{self, Platform};

pub(super) fn security_audit_log_check() -> Check {
    let path = mvm_core::audit::default_audit_log();
    let exists = std::path::Path::new(&path).exists();
    Check {
        name: "audit log",
        category: "security",
        ok: true, // informational
        info: if exists {
            format!("present at {path}")
        } else {
            format!("not yet created at {path}")
        },
    }
}

/// What a sweep of the host-lifecycle audit chains found. Separated from the
/// [`Check`] so the verdict mapping is testable without a keystore or an audit
/// directory.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AuditChainScan {
    /// Host-lifecycle chains whose signatures verified clean.
    pub(crate) verified: usize,
    /// Chains that failed verification, with the reason, most-relevant first.
    pub(crate) broken: Vec<(String, String)>,
    /// Set when the sweep could not run at all (no host signer key yet, or the
    /// audit directory is unreadable). Distinct from "found nothing broken".
    pub(crate) not_assessed: Option<String>,
    /// Chains verified by resuming from a checkpoint rather than from genesis.
    ///
    /// Tracked so the check can say what it actually did. A resumed walk takes
    /// the prefix on a stored value's word instead of re-deriving it from the
    /// all-zero anchor, so it is not the same statement as a full verification
    /// and must not be reported as one.
    pub(crate) resumed: usize,
    /// Retired segments whose handoffs were checked but whose interiors were
    /// not walked. Reported for the same reason as `resumed`: the check cannot
    /// be allowed to read as having attested more than it did.
    pub(crate) sealed_segments: usize,
    /// Chains carrying a corroborated prune record.
    pub(crate) pruned_chains: usize,
    /// Entries those prunes removed. Surfaced because a verified chain that is
    /// missing history on purpose is a different statement from a verified
    /// chain that has all of it, and only one of them is what an auditor
    /// assumes when they read "verifies".
    pub(crate) pruned_entries: u64,
}

/// Verification status of the chain-signed audit log.
///
/// This is the check that makes a damaged chain visible on its own terms. Until
/// it existed, an unverifiable chain surfaced only indirectly — as a checkpoint
/// verb refusing a record — which reads as a problem with that record rather
/// than with the ledger. A broken chain is a posture failure: every claim the
/// log is supposed to support is unprovable while it lasts.
pub(super) fn security_audit_chain_check() -> Check {
    audit_chain_check_from_scan(&scan_audit_chains())
}

/// Verify every host-lifecycle chain under the audit dir against the host
/// signer's public half.
///
/// Loads the signer only when its secret half is already on disk: a diagnostic
/// verb must not mint a signing key as a side effect of being run.
fn scan_audit_chains() -> AuditChainScan {
    let not_assessed = |reason: String| AuditChainScan {
        not_assessed: Some(reason),
        ..Default::default()
    };

    let dir = match mvm_hostd::audit::emitter::default_audit_dir() {
        Ok(d) => d,
        Err(e) => return not_assessed(format!("audit dir unresolved: {e}")),
    };
    let keys_dir = match mvm_hostd::audit::host_keypair::default_keys_dir() {
        Ok(d) => d,
        Err(e) => return not_assessed(format!("keys dir unresolved: {e}")),
    };
    if !keys_dir
        .join(mvm_hostd::audit::host_keypair::SECRET_FILENAME)
        .exists()
    {
        return not_assessed("no host signer key yet; nothing has been signed".to_string());
    }
    let signer = match mvm_hostd::audit::host_keypair::load_or_init() {
        Ok(s) => s,
        Err(e) => return not_assessed(format!("host signer unreadable: {e}")),
    };
    let read_dir = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return AuditChainScan::default(),
        Err(e) => return not_assessed(format!("reading {}: {e}", dir.display())),
    };

    // One entry per *chain*, not per file. A rotated chain is several files,
    // and verifying each in isolation would both re-walk history that cannot
    // change and — the part that matters — never notice that one of them is
    // missing, because each survivor verifies perfectly on its own.
    let mut bases: Vec<String> = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !mvm_core::config::is_host_lifecycle_chain(&path) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Folds a retired segment onto the chain it was split off from, so a
        // rotated chain is swept once rather than once per file. Sweeping per
        // file would also never notice a *missing* segment, because each
        // survivor verifies perfectly on its own.
        if let Some(base) = mvm_core::config::lifecycle_chain_base(name)
            && !bases.iter().any(|b| b == base)
        {
            bases.push(base.to_string());
        }
    }
    bases.sort();

    let mut scan = AuditChainScan::default();
    for base in &bases {
        let active = dir.join(format!("{base}.jsonl"));
        // Two halves, deliberately kept apart because they attest different
        // things and are reported separately.
        //
        // First the structure across segments: every handoff's signature and
        // every claimed predecessor hash, at O(segments) rather than O(entire
        // history). This is what catches a segment that was removed.
        let verified =
            match mvm_hostd::supervisor::verify_segment_topology(&dir, base, &signer.verifying) {
                Ok(verified) => verified,
                Err(e) => {
                    scan.broken
                        .push((active.display().to_string(), format!("{e:#}")));
                    continue;
                }
            };
        scan.sealed_segments += verified.segments.iter().filter(|r| !r.active).count();
        // A pruned chain verifies, and is also missing history on purpose. Both
        // are true, and reporting only the first would make "verifies" mean
        // something different for this host than for every other one.
        if let Some(pruned) = verified.pruned {
            scan.pruned_entries += pruned.entries;
            scan.pruned_chains += 1;
        }

        // Then the live segment's contents, resuming from a checkpoint when one
        // is available. `mvmctl trust audit verify` deliberately keeps the
        // genesis-anchored walk over every segment — full re-derivation is what
        // that command is for, and it is claim 8's witness.
        //
        // A chain whose active file is absent is mid-rotation: the sealed set
        // was just checked and the continuation has not landed yet. There is
        // nothing live to walk and nothing wrong.
        if !active.exists() {
            scan.verified += 1;
            continue;
        }
        let checkpoint = mvm_hostd::supervisor::audit_checkpoint::load(&active);
        match mvm_hostd::supervisor::verify_audit_chain_incremental(
            &active,
            &signer.verifying,
            checkpoint.as_ref(),
        ) {
            Ok(outcome) => {
                scan.verified += 1;
                if !outcome.walked_from_genesis {
                    scan.resumed += 1;
                }
                mvm_hostd::supervisor::audit_checkpoint::store(&active, &outcome.checkpoint);
            }
            Err(e) => scan
                .broken
                .push((active.display().to_string(), format!("{e:#}"))),
        }
    }
    scan.broken.sort();
    scan
}

/// Pure mapping: scan result → [`Check`]. A broken chain is the only `ok: false`
/// arm — an absent log and an un-assessable one are both honestly reported as
/// "not known to be broken", which is not the same as clean and does not claim
/// to be.
fn audit_chain_check_from_scan(scan: &AuditChainScan) -> Check {
    let name = "audit chain";
    let category = "security";
    if !scan.broken.is_empty() {
        let detail = scan
            .broken
            .iter()
            .map(|(path, why)| format!("{path} ({why})"))
            .collect::<Vec<_>>()
            .join("; ");
        return Check {
            name,
            category,
            ok: false,
            info: format!(
                "{} of {} chain(s) FAIL verification: {detail}. Entries behind the break anchor \
                 nothing, so records they audit now refuse as unprovable. Quarantine the file \
                 under a new name to preserve the evidence; it cannot be repaired without \
                 re-signing, and a chain that can be re-signed on demand cannot detect tampering.",
                scan.broken.len(),
                scan.broken.len() + scan.verified
            ),
        };
    }
    if let Some(reason) = &scan.not_assessed {
        return Check {
            name,
            category,
            ok: true,
            info: format!("not assessed ({reason})"),
        };
    }
    Check {
        name,
        category,
        ok: true,
        info: match (
            scan.verified,
            scan.resumed,
            scan.sealed_segments + scan.pruned_chains,
        ) {
            (0, _, _) => "no host-lifecycle chains yet".to_string(),
            (n, 0, 0) => format!("{n} chain(s) verify against the host signer"),
            // Both reductions are named. Neither is a full-history statement:
            // a resumed walk re-derived only the entries appended since the
            // last run, and a retired interior was not re-read at all — only
            // the handoff into and out of it. `mvmctl trust audit verify` is
            // the check that walks every segment from the first entry, and an
            // operator has to be able to tell which answer they are holding.
            (n, r, sealed) => {
                let mut caveats = Vec::new();
                if r > 0 {
                    caveats.push(format!("{r} verified incrementally since the last run"));
                }
                if scan.sealed_segments > 0 {
                    caveats.push(format!(
                        "{} retired segment(s) checked at their handoffs only, \
                         interiors not re-walked",
                        scan.sealed_segments
                    ));
                }
                // Named first among equals in the operator's mind: the others
                // are things this run did not re-check, but a prune is history
                // that no run can ever check again.
                if scan.pruned_chains > 0 {
                    caveats.push(format!(
                        "{} chain(s) are missing a deliberately pruned prefix of {} \
                         entr{}, which no longer verify at all",
                        scan.pruned_chains,
                        scan.pruned_entries,
                        if scan.pruned_entries == 1 { "y" } else { "ies" }
                    ));
                }
                let _ = sealed;
                format!(
                    "{n} chain(s) verify against the host signer ({}; `mvmctl trust audit \
                     verify` re-checks every segment from the first entry)",
                    caveats.join("; ")
                )
            }
        },
    }
}

/// Host full-disk-encryption check for encryption at rest.
///
/// `LocalBackend` volumes rely on host FDE for at-rest protection (we
/// deliberately don't roll our own per-volume crypto on dev boxes).
/// On a dev host this check is **informational/warning-only** — the
/// `ok` flag stays `true` so a non-FDE laptop can still run mvmctl,
/// but the report surfaces the gap so users can enable FileVault /
/// LUKS before relying on local volumes for sensitive data.
///
/// On mvmd workers the analogous check is **enforced** (refuses
/// `LocalVirtiofs` bucket creation when FDE is absent).
pub(super) fn security_host_fde_check() -> Check {
    let detection = detect_host_fde_status();
    Check {
        name: "host FDE (volumes at-rest)",
        category: "security",
        ok: true, // warn-only on a dev box
        info: detection.info,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostFdeStatus {
    pub(crate) enabled: bool,
    pub(crate) info: String,
}

impl HostFdeStatus {
    fn enabled(info: impl Into<String>) -> Self {
        Self {
            enabled: true,
            info: info.into(),
        }
    }

    fn not_enabled(info: impl Into<String>) -> Self {
        Self {
            enabled: false,
            info: info.into(),
        }
    }
}

/// Enforce encrypted backing for a LocalBackend volume mount.
///
/// Local virtio-fs volumes are plaintext while mounted in the guest, so the
/// backing directory itself must live on an encrypted filesystem or encrypted
/// device. Unknown detection fails closed here because mounting the volume is
/// the point where mvm would otherwise expose sensitive local data without the
/// documented at-rest guarantee.
pub(crate) fn require_local_volume_host_path_encrypted(path: &std::path::Path) -> Result<()> {
    let status = detect_host_path_encryption_status(path);
    if status.enabled {
        return Ok(());
    }
    anyhow::bail!(
        "LocalBackend volume mounts require the mounted host directory to live \
         on encrypted backing storage. {}",
        status.info
    )
}

/// The device node of the volume containing `path`, e.g. `/dev/disk3s5`.
///
/// `diskutil info` takes a device or a volume, **not an arbitrary directory**:
/// `diskutil info /Users/auser` exits 1 with "Could not find disk". Every
/// caller of the probe passes a directory, so without this resolution the
/// macOS arm could never succeed — and it reported the tool as unavailable
/// when the tool had run perfectly and simply rejected its argument.
#[cfg(target_os = "macos")]
fn macos_containing_device(path: &std::path::Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c_path` is a valid NUL-terminated string for the duration of the
    // call, and `buf` is a correctly-sized zeroed `statfs` the kernel fills in.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut buf) } != 0 {
        return None;
    }
    // SAFETY: on success the kernel leaves `f_mntfromname` NUL-terminated.
    let device = unsafe { std::ffi::CStr::from_ptr(buf.f_mntfromname.as_ptr()) };
    device
        .to_str()
        .ok()
        .map(str::to_string)
        .filter(|d| !d.is_empty())
}

#[cfg(not(target_os = "macos"))]
fn macos_containing_device(_path: &std::path::Path) -> Option<String> {
    None
}

pub(crate) fn detect_host_path_encryption_status(path: &std::path::Path) -> HostFdeStatus {
    let plat = platform::current();
    if matches!(plat, Platform::MacOS) {
        // Ask about the volume that holds the directory, not the directory.
        // Falling back to the path itself keeps the old behaviour when the
        // resolution fails rather than refusing outright.
        let target = macos_containing_device(path).unwrap_or_else(|| path.display().to_string());
        match std::process::Command::new("diskutil")
            .arg("info")
            .arg(&target)
            .output()
        {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                parse_macos_diskutil_encryption_status(path, &stdout)
            }
            // Ran, but rejected the argument. Distinct from "could not run it",
            // and conflating the two is what made this look environmental.
            Ok(out) => HostFdeStatus::not_enabled(format!(
                "diskutil could not report on {target} (for {}): {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim(),
            )),
            Err(e) => HostFdeStatus::not_enabled(format!(
                "could not run diskutil to check {}: {e}",
                path.display()
            )),
        }
    } else if matches!(plat, Platform::LinuxNative | Platform::LinuxNoKvm) {
        match std::process::Command::new("findmnt")
            .args(["-no", "SOURCE", "-T"])
            .arg(path)
            .output()
        {
            Ok(out) if out.status.success() => {
                let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match std::process::Command::new("lsblk")
                    .args(["-no", "TYPE", &dev])
                    .output()
                {
                    Ok(types) if types.status.success() => {
                        let s = String::from_utf8_lossy(&types.stdout);
                        parse_linux_volume_backing_types(path, &dev, &s)
                    }
                    _ => HostFdeStatus::not_enabled(format!(
                        "could not inspect block-device type chain for {} ({dev})",
                        path.display()
                    )),
                }
            }
            _ => HostFdeStatus::not_enabled(format!(
                "could not determine backing device for {} (findmnt unavailable)",
                path.display()
            )),
        }
    } else {
        HostFdeStatus::not_enabled("unsupported platform for encrypted-volume detection")
    }
}

/// Best-effort detection of host full-disk encryption.
///
/// macOS: `fdesetup status` returns "FileVault is On." when enabled.
/// Linux: `lsblk -no TYPE / 2>&1 | grep crypt` succeeds when the root
/// FS sits on a dm-crypt mapping. Both checks fail closed (return
/// "unknown") if the underlying tool is missing.
pub(crate) fn detect_host_fde_status() -> HostFdeStatus {
    let plat = platform::current();
    if matches!(plat, Platform::MacOS) {
        match std::process::Command::new("fdesetup")
            .arg("status")
            .output()
        {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                parse_filevault_status(&stdout)
            }
            Ok(_) | Err(_) => HostFdeStatus::not_enabled(
                "could not determine FileVault state (fdesetup unavailable)",
            ),
        }
    } else if matches!(plat, Platform::LinuxNative | Platform::LinuxNoKvm) {
        match std::process::Command::new("findmnt")
            .args(["-no", "SOURCE", "/"])
            .output()
        {
            Ok(out) if out.status.success() => {
                let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match std::process::Command::new("lsblk")
                    .args(["-no", "TYPE", &dev])
                    .output()
                {
                    Ok(types) if types.status.success() => {
                        let s = String::from_utf8_lossy(&types.stdout);
                        parse_linux_block_types(&dev, &s)
                    }
                    _ => HostFdeStatus::not_enabled(format!(
                        "could not inspect type chain for {dev}"
                    )),
                }
            }
            _ => {
                HostFdeStatus::not_enabled("could not determine root device (findmnt unavailable)")
            }
        }
    } else {
        HostFdeStatus::not_enabled("unsupported platform for FDE detection")
    }
}

fn parse_filevault_status(stdout: &str) -> HostFdeStatus {
    if stdout.contains("FileVault is On") {
        HostFdeStatus::enabled("FileVault enabled (LocalBackend volumes encrypted at rest)")
    } else {
        HostFdeStatus::not_enabled(format!(
            "FileVault appears OFF — run `sudo fdesetup enable` before storing \
             sensitive data in LocalBackend volumes ({})",
            stdout.trim()
        ))
    }
}

fn parse_linux_block_types(dev: &str, types: &str) -> HostFdeStatus {
    if types.lines().any(|l| l.trim() == "crypt") {
        HostFdeStatus::enabled(format!(
            "root device {dev} sits on a dm-crypt mapping (LUKS enabled; \
             LocalBackend volumes encrypted at rest)"
        ))
    } else {
        HostFdeStatus::not_enabled(format!(
            "root device {dev} does NOT appear to be encrypted — enable LUKS \
             on root before storing sensitive data in LocalBackend volumes"
        ))
    }
}

fn parse_linux_volume_backing_types(
    path: &std::path::Path,
    dev: &str,
    types: &str,
) -> HostFdeStatus {
    if types.lines().any(|l| l.trim() == "crypt") {
        HostFdeStatus::enabled(format!(
            "{} is backed by {dev}, which sits on a dm-crypt/LUKS mapping",
            path.display()
        ))
    } else {
        HostFdeStatus::not_enabled(format!(
            "{} is backed by {dev}, which does NOT appear to sit on a \
             dm-crypt/LUKS mapping",
            path.display()
        ))
    }
}

fn parse_macos_diskutil_encryption_status(
    path: &std::path::Path,
    diskutil_output: &str,
) -> HostFdeStatus {
    for line in diskutil_output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().to_ascii_lowercase();
        let encrypted = value.starts_with("yes") || value.starts_with("encrypted");
        if matches!(key, "FileVault" | "Encrypted") && encrypted {
            return HostFdeStatus::enabled(format!(
                "{} is on a macOS volume reported as encrypted ({key}: {})",
                path.display(),
                value
            ));
        }
    }
    HostFdeStatus::not_enabled(format!(
        "{} is not on a macOS volume reported as encrypted by diskutil",
        path.display()
    ))
}

/// The mvm root (`mvm_home`) should be mode 0700 — it is the single
/// tree the security model owns; every subdirectory inherits its
/// privacy from this boundary.
pub(super) fn security_data_dir_mode_check() -> Check {
    let dir = mvm_core::config::mvm_home();
    let Ok(meta) = std::fs::symlink_metadata(&dir) else {
        return Check {
            name: "data dir mode",
            category: "security",
            ok: false,
            info: format!("not present at {dir} — run `mvmctl bootstrap`"),
        };
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let expected = 0o700;
        Check {
            name: "data dir mode",
            category: "security",
            ok: mode == expected,
            info: if mode == expected {
                format!("0{mode:o} at {dir}")
            } else {
                format!("expected 0{expected:o}, got 0{mode:o} at {dir}")
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Check {
            name: "data dir mode",
            category: "security",
            ok: true,
            info: "non-Unix host; mode check skipped".to_string(),
        }
    }
}

/// Dev VM vsock proxy socket should be mode 0700.
pub(super) fn security_proxy_socket_mode_check() -> Check {
    let path = dev_vm_socket_path();
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return Check {
            name: "vsock socket mode",
            category: "security",
            ok: true,
            info: format!("dev VM not running (no socket at {path})"),
        };
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let expected = 0o700;
        Check {
            name: "vsock socket mode",
            category: "security",
            ok: mode == expected,
            info: if mode == expected {
                format!("0{mode:o}")
            } else {
                format!(
                    "expected 0{expected:o}, got 0{mode:o} — same-host other users may have access"
                )
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Check {
            name: "vsock socket mode",
            category: "security",
            ok: true,
            info: "non-Unix host; mode check skipped".to_string(),
        }
    }
}

/// Cached pre-built dev image presence (informational; absence triggers
/// a hash-verified download).
pub(super) fn security_dev_image_check() -> Check {
    let version = env!("CARGO_PKG_VERSION");
    let prebuilt_dir = format!("{}/prebuilt/v{version}", mvm_core::config::mvm_share_dir());
    let kernel = format!("{prebuilt_dir}/vmlinux");
    let rootfs = format!("{prebuilt_dir}/rootfs.ext4");
    let cached = std::path::Path::new(&kernel).exists() && std::path::Path::new(&rootfs).exists();
    Check {
        name: "pre-built dev image",
        category: "security",
        ok: true,
        info: if cached {
            format!("cached at {prebuilt_dir}")
        } else {
            "not cached; next `mvmctl bootstrap` will download + hash-verify".to_string()
        },
    }
}

/// `deny.toml` at the workspace root (supply-chain policy).
pub(super) fn security_deny_config_check() -> Check {
    let cwd = std::env::current_dir().ok();
    let found = cwd.as_deref().and_then(|start| {
        let mut cur: Option<&std::path::Path> = Some(start);
        while let Some(p) = cur {
            if p.join("deny.toml").exists() && p.join("Cargo.toml").exists() {
                return Some(p.to_path_buf());
            }
            cur = p.parent();
        }
        None
    });
    Check {
        name: "cargo-deny policy",
        category: "security",
        ok: true,
        info: match found {
            Some(p) => format!("deny.toml at {}", p.display()),
            None => "deny.toml not found from cwd (expected only in source checkouts)".to_string(),
        },
    }
}

pub(super) fn security_default_network_check() -> Check {
    let path = mvm_core::dev_network::network_path("default");
    let exists = std::path::Path::new(&path).exists();
    Check {
        name: "default dev network",
        category: "security",
        ok: true,
        info: if exists {
            "configured".to_string()
        } else {
            "not configured — run `mvmctl network create default`".to_string()
        },
    }
}

/// Claim 10: *no untrusted workload reaches the network unless
/// explicitly admitted by policy.* `NetworkPolicy::default()` is
/// `deny_all()` rather than `unrestricted()`, so the safe posture is
/// the one workloads get without opting in. This check makes the
/// runtime default visible in `mvmctl doctor` so the claim is
/// observably enforced rather than implicit in the codepath.
///
/// Pure read of the policy default — no I/O, no platform branching.
/// A future regression that flipped the default back to `unrestricted`
/// would surface here loudly.
pub(super) fn security_network_policy_default_check() -> Check {
    use mvm_core::policy::network_policy::NetworkPolicy;
    let default = NetworkPolicy::default();
    // `NetworkPolicy::deny_all()` constructs the canonical deny-all
    // shape; equality against that is the load-bearing assertion.
    // Comparing against the constructor rather than introspecting
    // variants keeps this check resilient to future variant adds.
    let is_deny_all = default == NetworkPolicy::deny_all();
    Check {
        name: "network policy default (claim 10)",
        category: "security",
        ok: is_deny_all,
        info: if is_deny_all {
            "deny_all (claim 10 holds — egress refused unless explicitly admitted)".to_string()
        } else {
            "unrestricted — claim 10 does NOT hold; ADR-001 claim-10 regression. \
             Workloads boot with open egress instead of refusing it unless \
             `machine run --net` / `--allow-host` admits a destination."
                .to_string()
        },
    }
}

/// What security profile a run gets when the user names none, and what that
/// grants.
///
/// The profile is per-run, so what `doctor` can usefully report is the
/// default — the posture a `mvmctl run` or `machine run` lands in without an
/// argument. It reads that default off `RunArgs::default()` and describes it
/// from `RunProfile::grants()`, rather than restating either: a doctor line
/// that repeats a policy in prose is one more copy to go stale, and this one
/// would go stale silently in the direction of claiming a tighter posture than
/// the tool has.
///
/// A `permissive` default would be a finding. It is the escape hatch, and
/// reaching it without an argument would mean the acknowledgement gate is the
/// only thing between a bare `run` and broad local execution.
pub(super) fn security_default_run_profile_check() -> Check {
    let profile = crate::commands::default_run_profile();
    let ok = profile != crate::commands::RunProfile::Permissive;
    Check {
        name: "default run profile",
        category: "security",
        ok,
        info: if ok {
            format!(
                "{} — {} (both `run` and `machine run`; override with --profile)",
                profile.as_str(),
                profile.summary()
            )
        } else {
            format!(
                "{} is the default — the escape hatch should never be reached without \
                 an explicit --profile",
                profile.as_str()
            )
        },
    }
}

/// `~/.mvm/snapshot.key` should be mode 0600.
///
/// Absence is informational — the file is created lazily on first
/// snapshot seal. Existence with looser perms is a security finding:
/// any local user could read the key and forge sidecars.
pub(super) fn security_snapshot_key_check() -> Check {
    let path = mvm_core::crypto::snapshot_hmac::default_key_path(std::path::Path::new(
        &mvm_core::config::mvm_home(),
    ));
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return Check {
            name: "snapshot HMAC key",
            category: "security",
            ok: true,
            info: format!(
                "not yet created at {} (lazy — created on first snapshot seal)",
                path.display()
            ),
        };
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let expected = 0o600;
        let len_ok = meta.len() == mvm_core::crypto::snapshot_hmac::HMAC_KEY_BYTES as u64;
        Check {
            name: "snapshot HMAC key",
            category: "security",
            ok: mode == expected && len_ok,
            info: if mode != expected {
                format!(
                    "expected mode 0{expected:o}, got 0{mode:o} at {} — \
                     a local-user-readable HMAC key can be used to forge sidecars",
                    path.display()
                )
            } else if !len_ok {
                format!(
                    "key file at {} is {} bytes (expected {}) — corrupt; rotate by deleting the file",
                    path.display(),
                    meta.len(),
                    mvm_core::crypto::snapshot_hmac::HMAC_KEY_BYTES
                )
            } else {
                format!("0{mode:o} at {}", path.display())
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Check {
            name: "snapshot HMAC key",
            category: "security",
            ok: true,
            info: "non-Unix host; mode check skipped".to_string(),
        }
    }
}

/// All template snapshot directories should be mode 0700.
/// Walks `~/.mvm/templates/*/artifacts/*/snapshot/`,
/// reports the first looser-perm directory found (or "all OK" /
/// "none built yet" otherwise).
pub(super) fn security_snapshot_dirs_check() -> Check {
    let templates_dir = mvm_core::domain::template::templates_base_dir();
    let templates_path = std::path::Path::new(&templates_dir);
    if !templates_path.exists() {
        return Check {
            name: "snapshot dir mode",
            category: "security",
            ok: true,
            info: format!("no templates directory at {templates_dir}"),
        };
    }

    let mut total = 0u32;
    let mut bad: Option<(std::path::PathBuf, u32)> = None;
    if let Ok(entries) = std::fs::read_dir(templates_path) {
        for tpl in entries.flatten() {
            let artifacts = tpl.path().join("artifacts");
            let Ok(rev_entries) = std::fs::read_dir(&artifacts) else {
                continue;
            };
            for rev in rev_entries.flatten() {
                let snap = rev.path().join("snapshot");
                if !snap.is_dir() {
                    continue;
                }
                total += 1;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::symlink_metadata(&snap) {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode != 0o700 && bad.is_none() {
                            bad = Some((snap, mode));
                        }
                    }
                }
            }
        }
    }

    if total == 0 {
        return Check {
            name: "snapshot dir mode",
            category: "security",
            ok: true,
            info: format!("no snapshots built yet under {templates_dir}"),
        };
    }
    match bad {
        Some((path, mode)) => Check {
            name: "snapshot dir mode",
            category: "security",
            ok: false,
            info: format!(
                "expected 0700, got 0{mode:o} at {} (1 of {total} snapshot dir{}; \
                 looser perms let local users tamper with snapshots)",
                path.display(),
                if total == 1 { "" } else { "s" }
            ),
        },
        None => Check {
            name: "snapshot dir mode",
            category: "security",
            ok: true,
            info: format!(
                "0700 across {total} snapshot dir{}",
                if total == 1 { "" } else { "s" }
            ),
        },
    }
}

/// macOS-only: every executable in the active VM launch set needs the
/// entitlement for its runtime role. Probes all paths from
/// `collect_sign_targets` so an unsigned supervisor is not left unreported.
/// Off macOS the check is n/a (returns the early-exit n/a `Check`).
pub(super) fn security_signing_check() -> Check {
    use mvm_runtime::codesign::{collect_sign_targets, entitlement_present};
    let targets = collect_sign_targets();
    // `entitlement_present` returns `None` off macOS for every path, so if
    // the first target gives `None` the whole check is n/a.
    let probed: Vec<(std::path::PathBuf, Option<bool>)> = targets
        .into_iter()
        .map(|target| {
            let r = entitlement_present(&target.path, target.required);
            (target.path, r)
        })
        .collect();
    signing_check_from_probes(&probed)
}

/// Pure mapping: per-target probe results → Check. Separate so tests can
/// drive it with fixture data without invoking codesign or the filesystem.
fn signing_check_from_probes(probes: &[(std::path::PathBuf, Option<bool>)]) -> Check {
    // All None → not on macOS; the question is n/a.
    if probes.iter().all(|(_, r)| r.is_none()) {
        return Check {
            name: "signing",
            category: "security",
            ok: true,
            info: "n/a (macOS only)".to_string(),
        };
    }
    // Collect names of targets that are verifiably unsigned (Some(false)).
    let unsigned: Vec<String> = probes
        .iter()
        .filter_map(|(p, r)| {
            if *r == Some(false) {
                Some(
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<unknown>")
                        .to_string(),
                )
            } else {
                None
            }
        })
        .collect();
    if unsigned.is_empty() {
        Check {
            name: "signing",
            category: "security",
            ok: true,
            info: "required VM entitlements present on all launch targets".to_string(),
        }
    } else {
        Check {
            name: "signing",
            category: "security",
            ok: false,
            info: format!(
                "required VM entitlements missing on: {} — reinstall or update mvmctl \
                 (advanced repair: `mvmctl env sign`)",
                unsigned.join(", ")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn local_volume_encryption_requirement_fails_closed_for_an_unknown_path() {
        let missing = std::path::Path::new("/definitely/missing/mvm-encryption-probe");
        let error = require_local_volume_host_path_encrypted(missing).unwrap_err();
        assert!(error.to_string().contains("encrypted backing storage"));
    }

    struct EnvGuard {
        _env: TestEnv,
        _tmp_root: Option<tempfile::TempDir>,
    }

    impl EnvGuard {
        fn new(root: Option<tempfile::TempDir>) -> Self {
            let mut env = TestEnv::new();
            if let Some(r) = root.as_ref() {
                env.set("MVM_HOME", r.path());
            }
            EnvGuard {
                _env: env,
                _tmp_root: root,
            }
        }
    }

    // ── audit_chain_check_from_scan unit tests ──────────────────────

    /// The point of the check: a damaged chain is a posture *failure*, not an
    /// informational line. It used to surface only as an unrelated verb
    /// refusing a record, which reads as a problem with that record.
    #[test]
    fn a_fully_walked_scan_does_not_mention_incremental_verification() {
        let scan = AuditChainScan {
            verified: 3,
            broken: vec![],
            not_assessed: None,
            resumed: 0,
            sealed_segments: 0,
            pruned_chains: 0,
            pruned_entries: 0,
        };
        let info = audit_chain_check_from_scan(&scan).info;
        assert!(info.contains("3 chain(s) verify"), "{info}");
        assert!(
            !info.contains("incrementally"),
            "a genesis-anchored sweep should not qualify itself: {info}"
        );
    }

    #[test]
    fn a_resumed_scan_says_so_rather_than_claiming_a_full_walk() {
        // The check must not report a resumed walk as a full-chain guarantee:
        // the prefix was taken on a stored checkpoint's word, not re-derived
        // from the genesis anchor.
        let scan = AuditChainScan {
            verified: 3,
            broken: vec![],
            not_assessed: None,
            resumed: 2,
            sealed_segments: 0,
            pruned_chains: 0,
            pruned_entries: 0,
        };
        let info = audit_chain_check_from_scan(&scan).info;
        assert!(info.contains("2 verified incrementally"), "{info}");
        assert!(
            info.contains("trust audit verify"),
            "it must point at the genesis-anchored check: {info}"
        );
    }

    #[test]
    fn a_broken_chain_fails_the_check_and_names_the_file() {
        let scan = AuditChainScan {
            verified: 2,
            broken: vec![(
                "/audit-root/local.jsonl".into(),
                "prev_hash mismatch at line 3".into(),
            )],
            not_assessed: None,
            resumed: 0,
            sealed_segments: 0,
            pruned_chains: 0,
            pruned_entries: 0,
        };
        let c = audit_chain_check_from_scan(&scan);
        assert!(!c.ok, "a broken chain is a posture failure: {}", c.info);
        assert!(c.info.contains("local.jsonl"), "{}", c.info);
        assert!(c.info.contains("prev_hash mismatch"), "{}", c.info);
        assert!(
            c.info.contains("1 of 3"),
            "must say how much of the ledger is affected: {}",
            c.info
        );
    }

    /// Recovery guidance must not read as "reset it": someone who can damage
    /// one line could then force a reset, which turns tamper-detection into
    /// tamper-erasure.
    #[test]
    fn the_broken_chain_guidance_says_quarantine_and_never_re_sign() {
        let scan = AuditChainScan {
            verified: 0,
            broken: vec![("local.jsonl".into(), "bad signature".into())],
            not_assessed: None,
            resumed: 0,
            sealed_segments: 0,
            pruned_chains: 0,
            pruned_entries: 0,
        };
        let info = audit_chain_check_from_scan(&scan).info;
        assert!(info.contains("Quarantine"), "{info}");
        assert!(
            info.contains("cannot detect tampering"),
            "must say why re-signing is not a repair: {info}"
        );
    }

    #[test]
    fn all_chains_verifying_reports_the_count_and_passes() {
        let scan = AuditChainScan {
            verified: 3,
            ..Default::default()
        };
        let c = audit_chain_check_from_scan(&scan);
        assert!(c.ok);
        assert!(c.info.contains('3'), "{}", c.info);
    }

    /// "Nothing signed yet" and "could not look" both pass, but neither may
    /// claim the chains verify — the check would then assert a posture it never
    /// established.
    #[test]
    fn an_unassessed_scan_passes_without_claiming_the_chains_verify() {
        let scan = AuditChainScan {
            not_assessed: Some("no host signer key yet; nothing has been signed".into()),
            ..Default::default()
        };
        let c = audit_chain_check_from_scan(&scan);
        assert!(c.ok);
        assert!(c.info.starts_with("not assessed"), "{}", c.info);
        assert!(
            !c.info.contains("verify against"),
            "must not claim verification it did not perform: {}",
            c.info
        );
    }

    /// An empty audit dir is a real, clean finding — distinct from not looking.
    #[test]
    fn no_chains_yet_is_distinct_from_not_assessed() {
        let c = audit_chain_check_from_scan(&AuditChainScan::default());
        assert!(c.ok);
        assert!(
            c.info.contains("no host-lifecycle chains yet"),
            "{}",
            c.info
        );
    }

    /// Once a chain has retired segments, the passing message has to say the
    /// retired interiors were not re-walked. "3 chain(s) verify" on its own
    /// would claim a full-history attestation the cheap check never performed.
    #[test]
    fn a_passing_scan_with_segments_says_what_it_did_not_re_walk() {
        let scan = AuditChainScan {
            verified: 1,
            sealed_segments: 4,
            ..Default::default()
        };
        let info = audit_chain_check_from_scan(&scan).info;
        assert!(info.contains("4 retired segment(s)"), "{info}");
        assert!(info.contains("handoffs only"), "{info}");
        assert!(info.contains("interiors not re-walked"), "{info}");
        assert!(
            info.contains("trust audit verify"),
            "must point at the verb that does walk them: {info}"
        );
    }

    /// The two reductions are independent, and a message naming only one would
    /// let the other pass as a full-history statement.
    #[test]
    fn a_scan_that_both_resumed_and_skipped_interiors_names_both() {
        let scan = AuditChainScan {
            verified: 2,
            resumed: 1,
            sealed_segments: 3,
            ..Default::default()
        };
        let info = audit_chain_check_from_scan(&scan).info;
        assert!(info.contains("1 verified incrementally"), "{info}");
        assert!(info.contains("3 retired segment(s)"), "{info}");
    }

    /// A broken chain outranks an un-assessable one: the finding that needs
    /// action must not be masked by the reason the sweep was incomplete.
    #[test]
    fn a_break_outranks_a_not_assessed_reason() {
        let scan = AuditChainScan {
            verified: 0,
            broken: vec![("local.jsonl".into(), "bad signature".into())],
            not_assessed: Some("partial sweep".into()),
            resumed: 0,
            sealed_segments: 0,
            pruned_chains: 0,
            pruned_entries: 0,
        };
        assert!(!audit_chain_check_from_scan(&scan).ok);
    }

    /// The sweep must not mint a signing key just because someone ran a
    /// diagnostic. On a fresh `MVM_HOME` it reports "not assessed" and leaves
    /// the keys dir alone.
    #[test]
    fn scanning_a_fresh_home_creates_no_host_signer_key() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let scan = scan_audit_chains();
        assert!(
            scan.not_assessed.is_some(),
            "a fresh home has nothing signed: {scan:?}"
        );
        assert!(
            !tmp.path()
                .join("keys")
                .join(mvm_hostd::audit::host_keypair::SECRET_FILENAME)
                .exists(),
            "doctor must not create a signing key as a side effect"
        );
    }

    // ── signing_check_from_probes unit tests ────────────────────────

    #[test]
    fn signing_check_all_none_is_na() {
        // Off macOS every probe returns None → n/a, ok: true.
        let probes = vec![(std::path::PathBuf::from("/usr/local/bin/mvmctl"), None)];
        let c = signing_check_from_probes(&probes);
        assert!(c.ok);
        assert!(c.info.contains("n/a"), "expected n/a, got: {}", c.info);
    }

    #[test]
    fn signing_check_all_signed_is_ok() {
        let probes = vec![
            (
                std::path::PathBuf::from("/usr/local/bin/mvmctl"),
                Some(true),
            ),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-hvf-supervisor"),
                Some(true),
            ),
        ];
        let c = signing_check_from_probes(&probes);
        assert!(c.ok, "all signed → ok; got: {}", c.info);
        assert!(
            c.info.contains("all launch targets"),
            "expected 'all launch targets', got: {}",
            c.info
        );
    }

    #[test]
    fn signing_check_one_unsigned_supervisor_is_not_ok() {
        // mvmctl signed, supervisor unsigned — doctor must NOT report OK.
        let probes = vec![
            (
                std::path::PathBuf::from("/usr/local/bin/mvmctl"),
                Some(true),
            ),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-hvf-supervisor"),
                Some(false),
            ),
        ];
        let c = signing_check_from_probes(&probes);
        assert!(!c.ok, "unsigned supervisor must fail; got: {}", c.info);
        assert!(
            c.info.contains("mvm-hvf-supervisor"),
            "info must name the unsigned target; got: {}",
            c.info
        );
        assert!(
            c.info.contains("mvmctl env sign"),
            "info must carry the remediation hint; got: {}",
            c.info
        );
    }

    #[test]
    fn signing_check_mixed_none_and_false_treats_false_as_unsigned() {
        // Some targets return None (probe failed / tooling unavailable),
        // others return Some(false) (verifiably unsigned). The None ones
        // must not be counted as "unsigned" — only confirmed Some(false)
        // targets appear in the remediation list.
        let probes = vec![
            (
                std::path::PathBuf::from("/usr/local/bin/mvmctl"),
                Some(true),
            ),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-libkrun-supervisor"),
                None,
            ),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-hvf-supervisor"),
                Some(false),
            ),
        ];
        let c = signing_check_from_probes(&probes);
        assert!(!c.ok, "at least one Some(false) → not ok; got: {}", c.info);
        assert!(
            c.info.contains("mvm-hvf-supervisor"),
            "must name the unsigned binary; got: {}",
            c.info
        );
        assert!(
            !c.info.contains("mvm-libkrun-supervisor"),
            "None probe must not be listed as unsigned; got: {}",
            c.info
        );
    }

    #[test]
    fn signing_check_all_unknown_probes_is_ok() {
        // All probes return None → on macOS this means codesign wasn't
        // available for every target (treated as "unknown, not a failure").
        // The n/a branch fires only when ALL are None.
        let probes = vec![
            (std::path::PathBuf::from("/usr/local/bin/mvmctl"), None),
            (
                std::path::PathBuf::from("/usr/local/bin/mvm-hvf-supervisor"),
                None,
            ),
        ];
        let c = signing_check_from_probes(&probes);
        assert!(c.ok, "all None → n/a, ok; got: {}", c.info);
    }

    #[test]
    fn signing_check_is_in_security_category() {
        let c = security_signing_check();
        assert_eq!(c.category, "security");
        assert_eq!(c.name, "signing");
    }

    #[cfg(unix)]
    #[test]
    fn security_data_dir_mode_check_reads_the_root_mode() {
        use std::os::unix::fs::PermissionsExt;
        let data = tempfile::tempdir().unwrap();
        std::fs::set_permissions(data.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let _g = EnvGuard::new(Some(data));
        let c = security_data_dir_mode_check();
        assert!(
            c.ok,
            "expected ok because data dir is 0700, got: {}",
            c.info
        );
        assert!(
            c.info.contains("0700"),
            "info should report the data dir's mode, got: {}",
            c.info
        );
    }

    #[test]
    fn default_run_profile_check_reports_the_profile_the_cli_actually_applies() {
        let c = security_default_run_profile_check();
        let profile = crate::commands::default_run_profile();
        assert!(c.ok, "a non-permissive default must pass");
        assert!(
            c.info.starts_with(profile.as_str()),
            "the line must lead with the profile the CLI applies: {}",
            c.info
        );
        assert!(
            c.info.contains(&profile.summary()),
            "and describe what it grants: {}",
            c.info
        );
        // The line claims both verbs agree. That was true only after they were
        // reconciled, so it is worth holding.
        assert_eq!(
            profile,
            crate::commands::RunProfile::Standard,
            "if the default moves, this line's claim about both verbs needs re-checking"
        );
    }

    #[test]
    fn security_network_policy_default_check_reports_claim_10_holding() {
        // Invariant: `NetworkPolicy::default()` returns
        // `deny_all`. If a future regression flips it back to
        // `unrestricted`, this check fails loudly in doctor — pinning
        // claim 10 against silent drift.
        let c = security_network_policy_default_check();
        assert_eq!(c.category, "security");
        assert!(c.ok, "claim 10 must hold; doctor saw: {}", c.info);
        assert!(
            c.info.contains("deny_all"),
            "info should call out deny_all; got: {}",
            c.info
        );
        assert!(
            c.info.contains("claim 10 holds"),
            "info should name claim 10 so operators searching the doctor \
             output for the claim find it; got: {}",
            c.info
        );
    }

    #[test]
    fn filevault_parser_accepts_on_status() {
        let status = parse_filevault_status("FileVault is On.\n");
        assert!(status.enabled, "expected enabled: {}", status.info);
        assert!(
            status.info.contains("encrypted at rest"),
            "info should state the at-rest guarantee, got: {}",
            status.info
        );
    }

    #[test]
    fn filevault_parser_rejects_off_status() {
        let status = parse_filevault_status("FileVault is Off.\n");
        assert!(!status.enabled, "expected disabled");
        assert!(
            status.info.contains("FileVault appears OFF"),
            "expected FileVault remediation, got: {}",
            status.info
        );
    }

    #[test]
    fn linux_fde_parser_accepts_crypt_in_device_chain() {
        let status = parse_linux_block_types("/dev/mapper/cryptroot", "disk\npart\ncrypt\n");
        assert!(status.enabled, "expected enabled: {}", status.info);
        assert!(
            status.info.contains("LUKS enabled"),
            "expected LUKS marker, got: {}",
            status.info
        );
    }

    #[test]
    fn linux_fde_parser_rejects_plain_device_chain() {
        let status = parse_linux_block_types("/dev/nvme0n1p2", "disk\npart\n");
        assert!(!status.enabled, "expected disabled");
        assert!(
            status.info.contains("does NOT appear to be encrypted"),
            "expected LUKS remediation, got: {}",
            status.info
        );
    }

    #[test]
    fn linux_volume_backing_parser_accepts_crypt_chain() {
        let path = std::path::Path::new("/volumes/work");
        let status =
            parse_linux_volume_backing_types(path, "/dev/mapper/mvm-volume-work", "crypt\n");
        assert!(status.enabled, "expected enabled: {}", status.info);
        assert!(
            status.info.contains("dm-crypt/LUKS"),
            "expected dm-crypt marker, got: {}",
            status.info
        );
    }

    #[test]
    fn linux_volume_backing_parser_rejects_plain_chain() {
        let path = std::path::Path::new("/volumes/work");
        let status = parse_linux_volume_backing_types(path, "/dev/sda2", "disk\npart\n");
        assert!(!status.enabled, "expected disabled");
        assert!(
            status.info.contains("does NOT appear"),
            "expected encrypted-backing refusal, got: {}",
            status.info
        );
    }

    /// The bug this guards: `diskutil info` takes a device or a volume, not a
    /// directory. Every caller passes a directory, so before this resolution
    /// the probe reported "diskutil unavailable" on every macOS host — for a
    /// tool that ran fine and rejected its argument. `mvmctl machine volume
    /// mount` refused every directory as a result.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_directory_resolves_to_the_device_of_its_containing_volume() {
        // A plain directory that is not itself a mount point is the shape that
        // failed; `/` is the shape that happened to work and hid it.
        let device = macos_containing_device(std::path::Path::new("/System/Volumes/Data"))
            .expect("a real directory resolves to a device");
        assert!(
            device.starts_with("/dev/"),
            "expected a device node, got {device}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_unresolvable_path_yields_no_device_rather_than_a_wrong_one() {
        assert_eq!(
            macos_containing_device(std::path::Path::new("/no/such/path/anywhere")),
            None
        );
    }

    #[test]
    fn macos_diskutil_parser_accepts_filevault_volume() {
        let path = std::path::Path::new("/Users/alice/volumes/work");
        let status = parse_macos_diskutil_encryption_status(
            path,
            "Device Identifier: disk3s1\nFileVault: Yes (Unlocked)\n",
        );
        assert!(status.enabled, "expected enabled: {}", status.info);
        assert!(
            status.info.contains("reported as encrypted"),
            "expected encrypted marker, got: {}",
            status.info
        );
    }

    #[test]
    fn macos_diskutil_parser_accepts_encrypted_volume() {
        let path = std::path::Path::new("/Volumes/secure-work");
        let status = parse_macos_diskutil_encryption_status(
            path,
            "Device Identifier: disk4s1\nEncrypted: Yes\n",
        );
        assert!(status.enabled, "expected enabled: {}", status.info);
    }

    #[test]
    fn macos_diskutil_parser_rejects_unencrypted_volume() {
        let path = std::path::Path::new("/Volumes/plain");
        let status = parse_macos_diskutil_encryption_status(
            path,
            "Device Identifier: disk4s1\nEncrypted: No\nFileVault: No\n",
        );
        assert!(!status.enabled, "expected disabled");
        assert!(
            status
                .info
                .contains("not on a macOS volume reported as encrypted"),
            "expected encrypted-backing refusal, got: {}",
            status.info
        );
    }
}
