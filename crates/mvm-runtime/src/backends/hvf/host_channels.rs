//! Host-side inputs the HVF supervisor threads into a guest boot.

use std::path::PathBuf;

/// Host-supplied boot inputs the supervisor threads into a guest: the vsock
/// channels (per-VM host→guest agent RPC socket, substitution-endpoint socket,
/// egress relay UDS) plus the kernel cmdline. Bundled so the boot entry stays
/// under the argument-count lint. The two socket paths fall back to the
/// `MVM_HVF_{AGENT,SUBSTITUTION}_SOCKET` env hooks when `None` (dev/live drivers);
/// the productionized path threads them through the supervisor config.
#[derive(Default)]
pub struct HostChannels {
    pub agent_socket: Option<PathBuf>,
    pub substitution_socket: Option<PathBuf>,
    /// Per-VM egress bridge UDS. When set, `EGRESS_PORT` relays here — the
    /// endpoint gates (claim-10) and substitutes secrets. `None` ⇒ egress fails
    /// closed at the bridge (an hvf VM must always carry a relay socket).
    pub egress_relay: Option<PathBuf>,
    /// Trusted-builder tier: relay egress without the per-workload byte-rate
    /// cap. False for every workload.
    pub trusted_builder_egress: bool,
    /// Per-VM host-services broker UDS. When set, `BROKER_PORT` relays here — the
    /// socket the host-agent daemon bound for this VM — so a guest `host.audit.v1`
    /// call reaches the broker. `None` ⇒ `BROKER_PORT` fails closed at the bridge.
    pub broker_socket: Option<PathBuf>,
    /// Additional host-dial listeners, including telemetry and admitted console
    /// data channels. Telemetry is present independently of console grants.
    pub console_data_sockets: Vec<(u32, PathBuf)>,
    /// Builder-tier control listeners: job dispatch and the resident daemon's
    /// typed channel, for a persistent builder VM. Empty for every workload.
    /// Rides the same host-dial bridge as the console ports — the guest listens,
    /// the host dials — and the two ranges never overlap.
    pub builder_control_sockets: Vec<(u32, PathBuf)>,
    /// Full kernel cmdline. `None` ⇒ the built-in [`default_bootargs`] (workload
    /// default: `init=/init`). A caller that boots an image expecting a different
    /// PID 1 — e.g. the builder rootfs, whose init is the static
    /// `/sbin/mvm-host-vm-init`, not the `/init` shell script — sets it here.
    /// `MVM_HVF_BOOTARGS` still overrides both (dev hook).
    pub cmdline: Option<String>,
    /// Guest RAM in MiB. `0` ⇒ the built-in default (512 MiB). A builder sets
    /// several GiB so `nix build` doesn't OOM.
    pub mem_mib: u32,
    /// Guest vCPUs. `0` ⇒ 1.
    ///
    /// Read by exactly two things that must agree: the device tree, which tells
    /// the guest how many CPUs exist, and the vCPU creation below. A tree that
    /// describes more CPUs than the VMM creates hangs the boot waiting for
    /// secondaries; fewer, and the extra vCPUs are never onlined.
    pub vcpus: u32,
    /// Read-only live host-directory shares as `(virtio-fs tag, host path)`.
    /// Host console log to mirror guest output into as the guest emits it.
    ///
    /// The whole-run transcript comes back in [`KernelBootResult::console`]
    /// either way; this is what makes it readable *before* the run loop
    /// returns, so a guest that never finishes booting can be diagnosed while
    /// it is still hung instead of only once it has been stopped. Opened
    /// write-only: the console carries guest output to the host and never the
    /// other way.
    pub console_log: Option<PathBuf>,
    /// Optional host-visible marker acknowledged after the run loop enters its
    /// pause hold. It is removed when resume is observed.
    pub pause_state: Option<PathBuf>,
    /// Host-side request file asking the paused run loop to serialize RAM and
    /// deterministic device/vCPU state.
    pub snapshot_request: Option<PathBuf>,
    /// Fixed supervisor-owned raw RAM output for a parent snapshot.
    pub snapshot_ram: Option<PathBuf>,
    /// Fixed supervisor-owned vCPU/device frame output for a parent snapshot.
    pub snapshot_frame: Option<PathBuf>,
    /// Verified saved state to restore instead of booting a kernel.
    pub restore: Option<super::snapshot::RestoreImage>,
    /// Written once the machine's state is fully applied and every vCPU is
    /// about to enter the guest. A restore's launcher waits for it, so a
    /// saved state the supervisor refuses surfaces as a failed restore rather
    /// than as a live pid that exits a moment later.
    pub ready_marker: Option<PathBuf>,
    /// Fixed supervisor-owned live-handoff control socket.
    pub handoff_socket: Option<PathBuf>,
    /// Trusted root from which the supervisor derives child channel paths.
    pub handoff_root: Option<PathBuf>,
    /// Host identity public key pinned for handoff authentication.
    pub handoff_verify_key: Option<String>,
}
