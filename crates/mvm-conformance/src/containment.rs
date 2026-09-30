//! Pure host-evidence primitives for the `DestructiveLabOnly` containment
//! scenario.
//!
//! The scenario boots a sealed guest on a kernel known vulnerable to
//! CVE-2026-80521 (an AF_UNIX `SCM_RIGHTS` garbage-collection use-after-free),
//! delivers and runs the public proof-of-concept inside that guest through
//! admission, and then asserts from *host* evidence that the guest-kernel
//! compromise did not cross the microVM boundary: the host filesystem,
//! processes and listeners are unchanged, a bystander sibling guest's rootfs
//! digest is unchanged, no egress connection was admitted, and the audit chain
//! is intact.
//!
//! The decision logic lives here — separated from the cucumber steps that
//! gather the raw observations — so it is a pure function the workspace test
//! run exercises without a live VM. The steps do the privileged, unrepeatable
//! work (boot a guest, run an exploit, read `/proc`); this module decides what
//! the numbers mean, and that is the part a regression would silently break.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// A snapshot of the host surface a guest-kernel compromise would perturb if it
/// crossed the boundary.
///
/// Deliberately coarse and cheap: the exact bytes of a watched set of host
/// files, the set of process command lines, and the set of listening sockets.
/// The claim is not "nothing on the host changed" — a busy host mutates
/// constantly — but "nothing the guest could reach changed", so the watched
/// file set is the narrow set of host paths the boundary is supposed to keep a
/// guest away from, chosen by the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostObservation {
    /// Watched host path → content digest (hex). A path that is absent in one
    /// snapshot and present in the other is itself a difference.
    pub files: BTreeMap<String, String>,
    /// Process identities (a stable rendering of each process, e.g.
    /// `pid:comm`), as a set so ordering and transient churn outside the set do
    /// not register.
    pub procs: BTreeSet<String>,
    /// Listening sockets, rendered as `proto:addr:port`, as a set.
    pub listeners: BTreeSet<String>,
}

impl HostObservation {
    /// Every way `after` differs from `self`, as human-readable lines. Empty
    /// means the host surface is unchanged, which is the passing outcome.
    ///
    /// New and removed elements are both reported: an exploit that *deletes* a
    /// host file or kills a host process has crossed the boundary exactly as
    /// much as one that adds a listener.
    #[must_use]
    pub fn drift(&self, after: &HostObservation) -> Vec<String> {
        let mut out = Vec::new();

        for (path, before_digest) in &self.files {
            match after.files.get(path) {
                None => out.push(format!("host file disappeared: {path}")),
                Some(after_digest) if after_digest != before_digest => {
                    out.push(format!("host file changed: {path}"));
                }
                Some(_) => {}
            }
        }
        for path in after.files.keys() {
            if !self.files.contains_key(path) {
                out.push(format!("host file appeared: {path}"));
            }
        }

        for gone in self.procs.difference(&after.procs) {
            out.push(format!("host process gone: {gone}"));
        }
        for added in after.procs.difference(&self.procs) {
            out.push(format!("new host process: {added}"));
        }

        for gone in self.listeners.difference(&after.listeners) {
            out.push(format!("host listener gone: {gone}"));
        }
        for added in after.listeners.difference(&self.listeners) {
            out.push(format!("new host listener: {added}"));
        }

        out
    }
}

/// What the audit chain says about the victim guest's outbound attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressVerdict {
    /// Count of recorded egress refusals — the positive evidence that the
    /// guest tried to reach the network and default-deny stopped it.
    pub refusals: usize,
    /// Any recorded egress *admissions*. Non-empty is a containment failure:
    /// an admitted outbound connection from a workload that declared no policy.
    pub admitted: Vec<String>,
}

impl EgressVerdict {
    /// Containment holds when nothing outbound was admitted. Refusals are
    /// welcome but not required — a PoC that never reaches the egress stage
    /// still must not have crossed it.
    #[must_use]
    pub fn contained(&self) -> bool {
        self.admitted.is_empty()
    }
}

/// Scan chain-signed audit lines for egress decisions.
///
/// Matches on the decision event token rather than parsing every field, so a
/// schema addition does not silently turn a refusal into an invisible line: an
/// `egress.admitted`/`egress.allowed` token anywhere is counted as an
/// admission, and `egress.refused`/`egress.denied` as a refusal. The caller
/// supplies already-verified chain lines; this only classifies them.
#[must_use]
pub fn classify_egress(audit_lines: &[String]) -> EgressVerdict {
    let mut refusals = 0usize;
    let mut admitted = Vec::new();
    for line in audit_lines {
        if line.contains("egress.admitted") || line.contains("egress.allowed") {
            admitted.push(line.clone());
        }
        if line.contains("egress.refused") || line.contains("egress.denied") {
            refusals += 1;
        }
    }
    EgressVerdict { refusals, admitted }
}

/// Whether an observed content digest matches a pinned one, case-insensitively.
///
/// The pins in `features/suites/s37_cve_containment/pins.toml` are lowercase
/// hex; a fetched artifact's digest may arrive from a tool that upper-cases.
/// Trims surrounding whitespace so a digest read from a `*.sha256` sidecar
/// (which carries a trailing newline) compares equal.
#[must_use]
pub fn digest_matches_pin(pinned_hex: &str, observed_hex: &str) -> bool {
    pinned_hex.trim().eq_ignore_ascii_case(observed_hex.trim())
}

// --- Victim boot mode ---------------------------------------------------------

/// The prefix of the pinned PoC's native compromise report. The full line is
/// validated by [`canary_lines`]; a prefix match alone is not evidence.
pub const CANARY_PREFIX: &str = "CONTAINER_ESCAPE_SUCCESS uid=";

/// The prefix of the line the detonation initramfs prints before running the
/// exploit, carrying the booted kernel's `uname -r` — the transcript proof
/// that the kernel the pin named is the kernel that actually booted.
pub const BOOT_MARKER_PREFIX: &str = "CVE-LAB-BOOT:";

/// The prefix of the line the detonation initramfs prints after the exploit
/// exits, carrying its exit code. Its presence, not its value, ends the
/// host-side wait: a guest that reaches it ran the PoC to completion.
pub const EXIT_MARKER_PREFIX: &str = "CVE-LAB-EXIT:";

/// Which low-level VMM boots the target kernel. The default is Firecracker;
/// QEMU/KVM is the fallback for PoCs written against a QEMU reference
/// environment (this PoC's prefetch timing oracle observed no timing
/// separation under Firecracker's CPU model; QEMU's `-cpu host` is the
/// environment the exploit was proven in). The containment posture is
/// identical: both drivers attach no NIC and wire no vsock egress channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VictimBackend {
    /// Low-level Firecracker driver (boots the uncompressed vmlinux).
    Firecracker,
    /// Low-level QEMU driver (boots the distro bzImage with `-cpu host`).
    Qemu,
}

impl VictimBackend {
    /// Parse the operator's selection (the `MVM_BDD_CVE_HYPERVISOR` value).
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "fc" | "firecracker" => Ok(Self::Firecracker),
            "qemu" => Ok(Self::Qemu),
            other => Err(format!(
                "unknown MVM_BDD_CVE_HYPERVISOR '{other}': expected 'fc' or 'qemu'"
            )),
        }
    }
}

/// How the victim guest boots, decided by the suite's kernel pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VictimBoot {
    /// No kernel is pinned: the admitted `machine run` path boots MVM's own
    /// workload kernel. The run witnesses containment of the delivered exploit
    /// on a kernel the PoC does not target, so a missing in-guest canary is
    /// expected and never fails the scenario.
    Admitted,
    /// `kernel.vmlinux_sha256` is pinned: the victim boots that exact kernel
    /// through the low-level driver — NIC-less, agentless, and
    /// deliberately outside admission — from a staged initramfs that runs the
    /// exploit. Booting the PoC's exact target kernel makes the in-guest
    /// canary load-bearing: its absence is a witnessed non-compromise, and
    /// the scenario fails (see [`require_witnessed_compromise`]).
    TargetKernel {
        /// The staged kernel image, digest-verified against the pin
        /// (vmlinux for Firecracker, the distro bzImage for QEMU).
        kernel: PathBuf,
        /// The staged detonation initramfs carrying the exploit.
        initramfs: PathBuf,
        /// Which low-level VMM performs the boot.
        backend: VictimBackend,
    },
}

impl VictimBoot {
    /// Whether this boot mode runs the PoC's exact target kernel.
    #[must_use]
    pub fn is_target_kernel(&self) -> bool {
        matches!(self, Self::TargetKernel { .. })
    }

    /// What the "no admitted egress" assertion rests on in this boot mode,
    /// printed into the transcript so the evidence basis is never implicit.
    ///
    /// The two modes genuinely differ: the admitted boot has a NIC-less guest
    /// whose only path off the box is the brokered vsock egress endpoint, so
    /// the audit chain's refusals are the evidence; the low-level boot wires
    /// no vsock channels at all, so the device model itself is the evidence —
    /// there is no egress endpoint for the guest to dial, admitted or not.
    /// The audit classification still runs in both modes: an `egress.admitted`
    /// line recorded during the detonation window is a failure regardless of
    /// how the victim booted.
    #[must_use]
    pub fn egress_evidence(&self) -> &'static str {
        match self {
            Self::Admitted => {
                "audit chain: the admission egress broker records every refusal, and \
                 any admission is a containment failure"
            }
            Self::TargetKernel { .. } => {
                "device model: the low-level boot attaches no NIC and wires no vsock \
                 egress channel, so the guest has no path off the host at all"
            }
        }
    }
}

/// A staged kernel the operator pointed the scenario at, its digest already
/// computed by the caller (file IO stays in the cucumber step).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCandidate {
    /// Path to the staged vmlinux.
    pub path: PathBuf,
    /// Its observed sha256, lowercase hex.
    pub sha256: String,
}

/// Decide the victim boot mode from the suite's kernel pin and the operator's
/// staged artifacts.
///
/// The pin is the switch: an empty `vmlinux_sha256` keeps the admitted boot
/// (the staged-kernel variables are transcript context, never boot inputs); a
/// set one demands both staged artifacts and a kernel whose observed digest
/// matches the pin. A mismatch refuses the boot: detonating on an unreviewed
/// kernel would witness nothing about the pinned one.
///
/// The Firecracker driver boots the uncompressed vmlinux, verified against
/// `vmlinux_pin`. The QEMU driver boots the distro bzImage instead (QEMU's
/// `-kernel` does not load a bare ELF), verified against `vmlinuz_pin` — the
/// bzImage is covered by the same index-verified .deb the vmlinux was
/// extracted from.
pub fn resolve_victim_boot(
    vmlinux_pin: &str,
    vmlinuz_pin: &str,
    kernel: Option<KernelCandidate>,
    initramfs: Option<PathBuf>,
    backend: VictimBackend,
) -> Result<VictimBoot, String> {
    if vmlinux_pin.trim().is_empty() {
        return Ok(VictimBoot::Admitted);
    }
    let kernel = kernel.ok_or_else(|| {
        "pins.toml kernel.vmlinux_sha256 is pinned but MVM_BDD_CVE_KERNEL is unset. \
         Stage the target kernel with scripts/stage-cve-2026-80521-lab.sh and export \
         the produced kernel path. See features/suites/s37_cve_containment/README.md."
            .to_string()
    })?;
    let expected_pin = match backend {
        VictimBackend::Firecracker => vmlinux_pin.trim().to_string(),
        VictimBackend::Qemu => {
            if vmlinuz_pin.trim().is_empty() {
                return Err(
                    "MVM_BDD_CVE_HYPERVISOR=qemu boots the distro bzImage, but pins.toml \
                     kernel.vmlinuz_sha256 is empty. The staging script prints the bzImage \
                     digest after extracting the pinned .deb; record it first."
                        .to_string(),
                );
            }
            vmlinuz_pin.trim().to_string()
        }
    };
    if !digest_matches_pin(&expected_pin, &kernel.sha256) {
        return Err(format!(
            "staged kernel digest does not match the pin.\n  pinned:   {}\n  observed: {}\n\
             Refusing to boot a kernel that is not the reviewed one.",
            expected_pin, kernel.sha256
        ));
    }
    let initramfs = initramfs.ok_or_else(|| {
        "pins.toml kernel.vmlinux_sha256 is pinned but MVM_BDD_CVE_INITRAMFS is unset. \
         The low-level boot has no admitted image machinery; the staging script \
         builds the detonation initramfs that carries the exploit. See \
         features/suites/s37_cve_containment/README.md."
            .to_string()
    })?;
    Ok(VictimBoot::TargetKernel {
        kernel: kernel.path,
        initramfs,
        backend,
    })
}

/// The guest's own compromise-report lines (the canary), verbatim and trimmed.
#[must_use]
pub fn canary_lines(guest_output: &str) -> Vec<&str> {
    guest_output
        .lines()
        .map(str::trim)
        .filter(|line| {
            let Some(rest) = line.strip_prefix(CANARY_PREFIX) else {
                return false;
            };
            let Some((uid, rest)) = rest.split_once(" host=") else {
                return false;
            };
            let Some((host, docker)) = rest.split_once(" docker=") else {
                return false;
            };
            uid == "0"
                && !host.is_empty()
                && !host.chars().any(char::is_whitespace)
                && matches!(docker, "yes" | "no")
        })
        .collect()
}

/// The boot-marker line the detonation initramfs printed, verbatim and trimmed.
#[must_use]
pub fn boot_marker_line(guest_output: &str) -> Option<&str> {
    guest_output
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(BOOT_MARKER_PREFIX))
}

/// Enforce the witness contract of the pinned-kernel boot. Detonating the PoC
/// on its exact target kernel and *not* observing the compromise canary is a
/// failed experiment, not a pass: either the staged kernel was not actually
/// vulnerable or the delivery broke, and in both cases the containment
/// assertions measured nothing.
///
/// The admitted boot keeps the canary a candidate observation only: there the
/// PoC runs on a kernel it does not target, so a missing canary says nothing.
pub fn require_witnessed_compromise(boot: &VictimBoot, guest_output: &str) -> Result<(), String> {
    if boot.is_target_kernel() && canary_lines(guest_output).is_empty() {
        return Err(
            "the vulnerable target kernel booted, but the exploit's compromise canary \
             never appeared on the guest console. A witnessed non-compromise on the \
             exact target kernel is a failed experiment: the containment assertions \
             measured nothing. Check the console log for a PoC crash, a kernel oops, \
             or a mismatched staged kernel."
                .to_string(),
        );
    }
    Ok(())
}

/// The exit code the detonation initramfs recorded for the exploit, when the
/// run reached the exit marker.
#[must_use]
pub fn exit_marker_code(guest_output: &str) -> Option<i32> {
    let line = guest_output
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(EXIT_MARKER_PREFIX))?;
    line.rsplit("rc=").next()?.trim().parse().ok()
}

/// Check that the boot marker names the pinned target kernel release. The
/// kernel's digest already proved its bytes; this proves those bytes are what
/// booted — a pin recorded against the wrong staged file fails here.
pub fn require_booted_kernel_matches_pin(
    guest_output: &str,
    target_version: &str,
) -> Result<(), String> {
    let marker = boot_marker_line(guest_output).ok_or_else(|| {
        format!(
            "the detonation initramfs printed no {BOOT_MARKER_PREFIX} line; cannot \
             confirm the booted kernel is the pinned target ({target_version})"
        )
    })?;
    if !marker.contains(target_version) {
        return Err(format!(
            "the booted kernel does not match the pinned target.\n  pinned target: {target_version}\n  boot marker:   {marker}\n\
             The staged vmlinux matched the pin's digest, so the pin was recorded \
             against the wrong kernel build."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(files: &[(&str, &str)], procs: &[&str], listeners: &[&str]) -> HostObservation {
        HostObservation {
            files: files
                .iter()
                .map(|(p, d)| ((*p).to_string(), (*d).to_string()))
                .collect(),
            procs: procs.iter().map(|s| (*s).to_string()).collect(),
            listeners: listeners.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn identical_snapshots_have_no_drift() {
        let a = obs(&[("/etc/passwd", "aa")], &["1:init"], &["tcp:0.0.0.0:22"]);
        assert!(a.drift(&a).is_empty());
    }

    #[test]
    fn a_changed_host_file_is_drift() {
        let before = obs(&[("/etc/passwd", "aa")], &[], &[]);
        let after = obs(&[("/etc/passwd", "bb")], &[], &[]);
        assert_eq!(before.drift(&after), vec!["host file changed: /etc/passwd"]);
    }

    #[test]
    fn an_appeared_or_disappeared_host_file_is_drift() {
        let before = obs(&[("/etc/passwd", "aa")], &[], &[]);
        let after = obs(&[("/tmp/pwned", "cc")], &[], &[]);
        let drift = before.drift(&after);
        assert!(drift.contains(&"host file disappeared: /etc/passwd".to_string()));
        assert!(drift.contains(&"host file appeared: /tmp/pwned".to_string()));
    }

    #[test]
    fn a_new_host_process_and_a_killed_one_are_both_drift() {
        let before = obs(&[], &["1:init", "2:agent"], &[]);
        let after = obs(&[], &["1:init", "9:reverse-shell"], &[]);
        let drift = before.drift(&after);
        assert!(drift.contains(&"host process gone: 2:agent".to_string()));
        assert!(drift.contains(&"new host process: 9:reverse-shell".to_string()));
    }

    #[test]
    fn a_new_host_listener_is_drift() {
        let before = obs(&[], &[], &["tcp:0.0.0.0:22"]);
        let after = obs(&[], &[], &["tcp:0.0.0.0:22", "tcp:0.0.0.0:4444"]);
        assert_eq!(
            before.drift(&after),
            vec!["new host listener: tcp:0.0.0.0:4444".to_string()]
        );
    }

    #[test]
    fn no_admitted_egress_is_contained_even_with_refusals() {
        let lines = vec![
            r#"{"event":"egress.refused","dest":"depthfirst.com:443"}"#.to_string(),
            r#"{"event":"plan.launched"}"#.to_string(),
        ];
        let verdict = classify_egress(&lines);
        assert_eq!(verdict.refusals, 1);
        assert!(verdict.contained());
    }

    #[test]
    fn an_admitted_egress_breaks_containment() {
        let lines = vec![r#"{"event":"egress.admitted","dest":"1.2.3.4:4444"}"#.to_string()];
        let verdict = classify_egress(&lines);
        assert!(!verdict.contained());
        assert_eq!(verdict.admitted.len(), 1);
    }

    #[test]
    fn a_run_with_no_egress_records_is_still_contained() {
        let verdict = classify_egress(&[]);
        assert_eq!(verdict.refusals, 0);
        assert!(verdict.contained());
    }

    #[test]
    fn pin_comparison_ignores_case_and_surrounding_whitespace() {
        assert!(digest_matches_pin(
            "291ece1b9632016c1fd4a4f29eba1764acfa2012fa3c417b29f38fb3d73d4965",
            "  291ECE1B9632016C1FD4A4F29EBA1764ACFA2012FA3C417B29F38FB3D73D4965\n"
        ));
        assert!(!digest_matches_pin("aa", "bb"));
    }

    // --- Victim boot mode ---------------------------------------------------

    fn candidate(sha: &str) -> KernelCandidate {
        KernelCandidate {
            path: PathBuf::from("/lab/vmlinux"),
            sha256: sha.to_string(),
        }
    }

    #[test]
    fn an_empty_kernel_pin_keeps_the_admitted_boot() {
        for pin in ["", "   ", "\n"] {
            let boot = resolve_victim_boot(pin, "", None, None, VictimBackend::Firecracker)
                .expect("empty pin admits");
            assert_eq!(boot, VictimBoot::Admitted);
            assert!(!boot.is_target_kernel());
        }
    }

    #[test]
    fn an_empty_kernel_pin_ignores_staged_kernel_env_vars() {
        // The admitted path cannot honor a kernel path; the staged artifacts
        // are transcript context there, not a boot input.
        let boot = resolve_victim_boot(
            "",
            "",
            Some(candidate("aa")),
            Some(PathBuf::from("/lab/initrd")),
            VictimBackend::Firecracker,
        )
        .expect("empty pin admits");
        assert_eq!(boot, VictimBoot::Admitted);
    }

    #[test]
    fn a_pinned_kernel_without_a_staged_vmlinux_fails_fast_with_staging_instructions() {
        let err = resolve_victim_boot(
            "aa",
            "",
            None,
            Some(PathBuf::from("/lab/initrd")),
            VictimBackend::Firecracker,
        )
        .expect_err("a pinned kernel demands MVM_BDD_CVE_KERNEL");
        assert!(err.contains("MVM_BDD_CVE_KERNEL"), "got: {err}");
        assert!(err.contains("stage-cve-2026-80521-lab.sh"), "got: {err}");
    }

    #[test]
    fn a_pinned_kernel_with_a_digest_mismatch_is_refused() {
        let err = resolve_victim_boot(
            "aa",
            "",
            Some(candidate("bb")),
            Some(PathBuf::from("/lab/initrd")),
            VictimBackend::Firecracker,
        )
        .expect_err("a mismatched staged kernel must not boot");
        assert!(err.contains("does not match the pin"), "got: {err}");
    }

    #[test]
    fn a_pinned_kernel_without_a_staged_initramfs_fails_fast() {
        let err = resolve_victim_boot(
            "aa",
            "",
            Some(candidate("aa")),
            None,
            VictimBackend::Firecracker,
        )
        .expect_err("a pinned kernel demands MVM_BDD_CVE_INITRAMFS");
        assert!(err.contains("MVM_BDD_CVE_INITRAMFS"), "got: {err}");
    }

    #[test]
    fn a_pinned_kernel_with_verified_staged_artifacts_selects_the_target_kernel_boot() {
        let boot = resolve_victim_boot(
            "  AA \n",
            "",
            Some(candidate("aa")),
            Some(PathBuf::from("/lab/initrd.cpio.gz")),
            VictimBackend::Firecracker,
        )
        .expect("verified staged artifacts select the target-kernel boot");
        assert_eq!(
            boot,
            VictimBoot::TargetKernel {
                kernel: PathBuf::from("/lab/vmlinux"),
                initramfs: PathBuf::from("/lab/initrd.cpio.gz"),
                backend: VictimBackend::Firecracker,
            }
        );
        assert!(boot.is_target_kernel());
    }

    #[test]
    fn the_qemu_backend_verifies_the_bzimage_against_its_own_pin() {
        let boot = resolve_victim_boot(
            "aa",
            "  BB \n",
            Some(candidate("bb")),
            Some(PathBuf::from("/lab/initrd.cpio.gz")),
            VictimBackend::Qemu,
        )
        .expect("a verified bzImage selects the qemu target-kernel boot");
        assert_eq!(
            boot,
            VictimBoot::TargetKernel {
                kernel: PathBuf::from("/lab/vmlinux"),
                initramfs: PathBuf::from("/lab/initrd.cpio.gz"),
                backend: VictimBackend::Qemu,
            }
        );
    }

    #[test]
    fn the_qemu_backend_requires_the_bzimage_pin() {
        let err = resolve_victim_boot(
            "aa",
            "",
            Some(candidate("aa")),
            Some(PathBuf::from("/lab/initrd")),
            VictimBackend::Qemu,
        )
        .expect_err("qemu mode without a bzImage pin must refuse");
        assert!(err.contains("vmlinuz_sha256"), "got: {err}");
    }

    #[test]
    fn the_qemu_backend_refuses_a_bzimage_digest_mismatch() {
        let err = resolve_victim_boot(
            "aa",
            "bb",
            Some(candidate("cc")),
            Some(PathBuf::from("/lab/initrd")),
            VictimBackend::Qemu,
        )
        .expect_err("a mismatched bzImage must not boot");
        assert!(err.contains("does not match the pin"), "got: {err}");
    }

    #[test]
    fn backend_parsing_accepts_documented_spellings_and_rejects_the_rest() {
        assert_eq!(
            VictimBackend::parse("").expect("empty defaults"),
            VictimBackend::Firecracker
        );
        assert_eq!(
            VictimBackend::parse("FC").expect("case-insensitive"),
            VictimBackend::Firecracker
        );
        assert_eq!(
            VictimBackend::parse(" qemu ").expect("trimmed"),
            VictimBackend::Qemu
        );
        assert!(VictimBackend::parse("kvm").is_err());
    }

    #[test]
    fn each_boot_mode_states_its_egress_evidence_basis() {
        assert!(
            VictimBoot::Admitted
                .egress_evidence()
                .contains("audit chain")
        );
        let target = VictimBoot::TargetKernel {
            kernel: PathBuf::from("/lab/vmlinux"),
            initramfs: PathBuf::from("/lab/initrd"),
            backend: VictimBackend::Firecracker,
        };
        let basis = target.egress_evidence();
        assert!(basis.contains("no NIC"), "got: {basis}");
        assert!(basis.contains("no vsock egress channel"), "got: {basis}");
    }

    // --- Canary witness contract -----------------------------------------------

    #[test]
    fn canary_lines_picks_out_only_the_exploits_own_report() {
        let output = "kernel boot noise\n\
                      CVE-LAB-BOOT: kernel=7.0.0-31-generic\n\
                      CONTAINER_ESCAPE_SUCCESS uid=0 host=mvm docker=no\n\
                      CVE-LAB-EXIT: rc=0\n";
        assert_eq!(
            canary_lines(output),
            vec!["CONTAINER_ESCAPE_SUCCESS uid=0 host=mvm docker=no"]
        );
        assert!(canary_lines("no canary here\nCVE-LAB-EXIT: rc=1\n").is_empty());
        assert!(
            canary_lines(
                "prefix CONTAINER_ESCAPE_SUCCESS uid=0 host=mvm docker=no\n\
                 CONTAINER_ESCAPE_SUCCESS uid=1000 host=mvm docker=no\n\
                 CONTAINER_ESCAPE_SUCCESS uid=0 host=mvm docker=maybe\n"
            )
            .is_empty(),
            "embedded, non-root, and malformed native reports are not evidence"
        );
    }

    #[test]
    fn the_admitted_boot_treats_a_missing_canary_as_a_candidate_observation() {
        require_witnessed_compromise(&VictimBoot::Admitted, "no canary here\n")
            .expect("the admitted boot never fails on a missing canary");
    }

    #[test]
    fn the_target_kernel_boot_fails_when_the_canary_never_appears() {
        let boot = VictimBoot::TargetKernel {
            kernel: PathBuf::from("/lab/vmlinux"),
            initramfs: PathBuf::from("/lab/initrd"),
            backend: VictimBackend::Firecracker,
        };
        let err = require_witnessed_compromise(
            &boot,
            "CVE-LAB-BOOT: kernel=7.0.0-31-generic\nCVE-LAB-EXIT: rc=1\n",
        )
        .expect_err("a witnessed non-compromise on the target kernel is a failed experiment");
        assert!(err.contains("failed experiment"), "got: {err}");
        require_witnessed_compromise(&boot, "CONTAINER_ESCAPE_SUCCESS uid=0 host=mvm docker=no\n")
            .expect("a printed canary satisfies the witness contract");
    }

    #[test]
    fn the_exit_marker_reports_the_exploits_exit_code() {
        assert_eq!(
            exit_marker_code("CVE-LAB-EXIT: rc=0\n"),
            Some(0),
            "a completed run reports its code"
        );
        assert_eq!(exit_marker_code("CVE-LAB-EXIT: rc=137\n"), Some(137));
        assert_eq!(
            exit_marker_code("no marker\n"),
            None,
            "a run that never reached the marker reports nothing"
        );
        assert_eq!(exit_marker_code("CVE-LAB-EXIT: rc=abc\n"), None);
        assert_eq!(exit_marker_code("noise CVE-LAB-EXIT: rc=0\n"), None);
    }

    #[test]
    fn the_boot_marker_must_name_the_pinned_target_kernel() {
        let output = "CVE-LAB-BOOT: kernel=7.0.0-31-generic arch=x86_64\n";
        require_booted_kernel_matches_pin(output, "7.0.0-31-generic")
            .expect("the booted kernel matches the pin");

        let err = require_booted_kernel_matches_pin("no marker here\n", "7.0.0-31-generic")
            .expect_err("a missing boot marker cannot confirm the target kernel");
        assert!(err.contains("CVE-LAB-BOOT"), "got: {err}");

        let err = require_booted_kernel_matches_pin(
            "CVE-LAB-BOOT: kernel=6.8.0-139-generic arch=x86_64\n",
            "7.0.0-31-generic",
        )
        .expect_err("a different booted kernel fails against the pin");
        assert!(err.contains("does not match"), "got: {err}");

        let err = require_booted_kernel_matches_pin(
            "noise CVE-LAB-BOOT: kernel=7.0.0-31-generic arch=x86_64\n",
            "7.0.0-31-generic",
        )
        .expect_err("an embedded marker is not boot evidence");
        assert!(err.contains("printed no"), "got: {err}");
    }
}
