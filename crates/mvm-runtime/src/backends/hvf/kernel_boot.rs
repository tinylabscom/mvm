//! Boot a real arm64 Linux `Image` under HVF and capture earlycon output.
//!
//! Loads the kernel and a minimal DTB into guest RAM, sets the arm64 boot
//! registers (`x0`=DTB, `PC`=entry), and runs the vCPU with the console run
//! loop: PL011 MMIO is captured, PSCI HVCs are stubbed, unmodeled MMIO is
//! read-as-zero / write-ignore so the kernel keeps progressing, and a watchdog
//! thread forces the vCPU out after a timeout (a booting kernel never returns on
//! its own). The captured bytes are the kernel's earlycon output — proof that
//! real Linux boots and prints on this backend.
//!
//! Creates HVF's in-kernel GICv3 + arch timer and sets the vCPU's `MPIDR_EL1`
//! affinity to match the redistributor, so the kernel's interrupt + timer
//! subsystems come fully up: a real kernel boots all the way through driver and
//! filesystem init to `prepare_namespace`, driving the PL011 console throughout.
//! It then panics mounting the root fs because none is supplied — providing a
//! root filesystem (initramfs / virtio-blk) is the next slice.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::HvfError;
#[cfg(test)]
use super::guest_ram::HVF_PAGE_SIZE;
use super::guest_ram::{GuestRam, page_rounded_len};
use super::hv_impl::{HvfHandle, HvfVcpu};
use super::snapshot::HVF_SNAPSHOT_BACKEND_KIND;
use super::sys::*;
use super::vcpu::esr_ec;
use super::{BootFault, default_bootargs, default_virtiofs_bootargs};
use crate::vmm::device::Pl011;
use crate::vmm::device_state::capture_device_states;
use crate::vmm::hv::{CoreReg, HypervisorVcpu, SysReg, VcpuHandle};
use crate::vmm::run::{self, RunControl, RunDevice, RunOutcome};
use crate::vmm::virtio::{DiskImage, VirtioBlk, VirtioFs};
use crate::vmm::virtio_rng::VirtioRng;
use crate::vmm::vsock::VirtioVsock;
use crate::vmm::{fdt, kernel_image};
use mvm_core::vcpu_quota::VcpuQuotaRecord;
use mvm_vmm::quota::{QuotaConfig, QuotaPolicy, ThreadCpuHandle, VcpuQuota};

/// Guest RAM base (2 GiB, per the aarch64 Linux boot convention). The GIC +
/// PL011 sit below RAM so their accesses fault out as MMIO.
const RAM_BASE: u64 = 0x8000_0000;
/// Default guest RAM (512 MiB) when the caller specifies none — enough for a
/// demo/agent boot. A builder overrides it (a `nix build` OOMs at 512 MiB).
const DEFAULT_RAM_SIZE: usize = 0x2000_0000;

/// Guest RAM in bytes for `mem_mib` MiB, or the default when `mem_mib` is 0.
/// A MiB is a multiple of the 16 KiB hypervisor page size, so the result is
/// always page-aligned.
fn ram_size_bytes(mem_mib: u32) -> usize {
    if mem_mib == 0 {
        DEFAULT_RAM_SIZE
    } else {
        (mem_mib as usize) * 1024 * 1024
    }
}
/// Linux aarch64 loads/enters the kernel at RAM start + 0x80000.
const KERNEL_LOAD_OFFSET: u64 = 0x8_0000;
/// DTB reserved window at the top of RAM (matches `fdt::FDT_MAX_SIZE` budget).
const FDT_MAX_SIZE: u64 = 0x20_0000;
/// Preferred initramfs load offset within RAM. Smaller guests may not extend to
/// 256 MiB, so boot placement falls back to the first 2 MiB-aligned region after
/// the kernel rather than rejecting an otherwise valid arm64 image.
const PREFERRED_INITRD_OFFSET: u64 = 0x1000_0000;
const INITRD_ALIGNMENT: usize = 0x20_0000;
const UART_BASE: u64 = fdt::SERIAL_MMIO_BASE;
/// virtio-mmio device windows (above the GIC, below RAM) + their SPIs.
const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
const VIRTIO_IRQ: u32 = 48;
const VSOCK_MMIO_BASE: u64 = 0x0a00_0200;
const VSOCK_IRQ: u32 = 49;
/// virtio-fs windows start above the disk band (MAX_DISKS=6 → up to
/// base+6*stride) and vsock. The first slot is the optional virtio-fs root;
/// following slots are live user directory shares.
const FS_MMIO_BASE: u64 = VIRTIO_MMIO_BASE + 7 * MMIO_STRIDE;
const FS_IRQ: u32 = 55;
/// Maximum number of user virtio-fs shares in one HVF guest. The bound keeps the
/// MMIO and SPI allocations fixed and leaves the entropy device at a stable slot.
const MAX_VIRTIOFS_SHARES: usize = 8;
/// The entropy device follows every optional disk/vsock/virtio-fs window, so its
/// stable address cannot collide with a device combination selected at runtime.
const RNG_MMIO_BASE: u64 = VIRTIO_MMIO_BASE + (8 + MAX_VIRTIOFS_SHARES as u64) * MMIO_STRIDE;
const RNG_IRQ: u32 = FS_IRQ + MAX_VIRTIOFS_SHARES as u32 + 1;
/// virtio-mmio window stride; each device occupies one 0x200 slot.
const MMIO_STRIDE: u64 = 0x200;
/// Max virtio-blk devices (`/dev/vda`..). The builder-with-runtime-overlay path
/// needs six: rootfs, nix-store, input, output, the read-only runtime overlay,
/// and the per-boot FlowMux identity drive.
const MAX_DISKS: usize = 6;

/// MMIO base + SPI for virtio-blk device `i` (`/dev/vda` = 0). Disk 0 keeps the
/// original single-disk window; disks 1+ sit *above* the vsock slot, so vsock's
/// address/IRQ stay fixed and the live-verified agent/egress path is untouched.
fn disk_mmio(i: usize) -> (u64, u32) {
    if i == 0 {
        (VIRTIO_MMIO_BASE, VIRTIO_IRQ)
    } else {
        (
            VIRTIO_MMIO_BASE + (i as u64 + 1) * MMIO_STRIDE,
            VIRTIO_IRQ + i as u32 + 1,
        )
    }
}

const PSCI_VERSION_FN: u64 = 0x8400_0000;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;

/// Raises a device SPI on the process-global in-kernel GIC — the [`IrqLine`] the
/// vsock host-I/O thread uses to interrupt the guest off the vCPU exit path
/// (mirrors the vCPU-path `set_irq` closure below). Zero-sized: the GIC is a
/// process-global HVF resource, so no per-VM handle is needed.
struct GicSpi;

impl crate::vmm::vsock::IrqLine for GicSpi {
    fn signal(&self, spi: u32) {
        // SAFETY: FFI to the process-global in-kernel GIC created for this VM; it
        // is thread-safe, so the host-I/O thread may assert an SPI directly.
        unsafe {
            hv_gic_set_spi(spi, true);
        }
    }
}

/// Outcome of a kernel boot attempt (with boot diagnostics).
#[derive(Debug, Clone, Default)]
pub struct KernelBootResult {
    /// Bytes the kernel emitted via the emulated PL011 (its earlycon output).
    pub console: Vec<u8>,
    /// Final vCPU exit reason.
    pub exit_reason: hv_exit_reason_t,
    /// PSCI HVC calls serviced.
    pub hvc_calls: usize,
    /// True if the watchdog forced the run to stop (expected for a live boot).
    pub stopped_by_watchdog: bool,
    /// Synchronous exceptions other than HVC/data-abort.
    pub other_exceptions: usize,
    /// PSCI function ids requested (capped).
    pub psci_fns: Vec<u64>,
    /// Distinct exception classes seen on the "other" path (capped).
    pub other_ecs: Vec<u32>,
    /// vCPU PC when the run ended.
    pub final_pc: u64,
    /// Bytes the guest sent to the host over virtio-vsock.
    pub vsock_received: Vec<u8>,
    /// Workload exit code, if the guest reported one over the workload-exit vsock
    /// port (the transient run-to-exit signal). `None` for a run that ended by
    /// timeout/stop without a workload-exit report.
    pub workload_exit_code: Option<i32>,
    /// Host-resident bytes backing the guest RAM mapping at boot completion.
    /// `None` on platforms without a resident-page query.
    pub resident_ram_bytes: Option<usize>,
    /// Monotonic time spent installing a private restore-RAM mapping, in
    /// microseconds. `None` when the boot did not restore RAM.
    pub restore_mapping_micros: Option<u64>,
    /// Internal supervisor shutdown spans. Present when the watchdog stopped a
    /// live run; absent for setup failures and ordinary guest exits.
    pub shutdown_timing: Option<KernelShutdownTiming>,
}

/// Internal spans between the watchdog observing stop and Hypervisor.framework
/// releasing the VM. File persistence happens in the detached supervisor and
/// is measured there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelShutdownTiming {
    /// From the watchdog observing `stop` and forcing a vCPU exit until the run
    /// loop returns. The preceding flag-observation delay is bounded by the
    /// watchdog's 5 ms interval.
    pub watchdog_to_vcpu_exit: Duration,
    /// Time spent joining the watchdog after the run loop returned.
    pub watchdog_join: Duration,
    /// Time spent waking and joining the event-driven host-I/O thread.
    pub io_thread_join: Duration,
    /// Time spent destroying the vCPU.
    pub vcpu_destroy: Duration,
    /// Time spent destroying the process-global HVF VM.
    pub vm_destroy: Duration,
}

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
    /// Dev-only host console listeners: one `(guest_port, host_socket)` per console
    /// data port the interactive PTY may reach. Populated only for a `dev_console`
    /// machine; empty for a sealed prod config, so nothing is bound (claim 15).
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
    /// When set, serve this host directory (the unpacked+injected OCI tree) to
    /// the guest as a read-only **virtiofs root** instead of a block rootfs — the
    /// Plan-223 dev-tier boot. No virtio-blk disk is attached; the default
    /// cmdline becomes `rootfstype=virtiofs root=mvmroot`.
    pub virtiofs_root: Option<PathBuf>,
    /// Read-only live host-directory shares as `(virtio-fs tag, host path)`.
    pub virtiofs_shares: Vec<(String, PathBuf)>,
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
    /// Raw parent RAM file to map privately for a restored child.
    pub restore_ram: Option<PathBuf>,
    /// Complete parent frame to restore into a fresh child VMM.
    pub restore_frame: Option<PathBuf>,
    /// Fixed supervisor-owned live-handoff control socket.
    pub handoff_socket: Option<PathBuf>,
    /// Trusted root from which the supervisor derives child channel paths.
    pub handoff_root: Option<PathBuf>,
    /// Host identity public key pinned for handoff authentication.
    pub handoff_verify_key: Option<String>,
}

static NEVER_STOP: AtomicBool = AtomicBool::new(false);
static NEVER_PAUSE: AtomicBool = AtomicBool::new(false);

/// Inputs for a persistent HVF kernel boot. Grouped so pause/stop/channel
/// control stays explicit without growing a positional argument list.
pub struct KernelBootUntilParams<'a> {
    kernel: KernelImageSource<'a>,
    initramfs: Option<&'a [u8]>,
    disks: Vec<DiskImage>,
    vsock: bool,
    timeout: Duration,
    stop: &'static AtomicBool,
    paused: &'static AtomicBool,
    channels: HostChannels,
    /// CPU share to enforce via the in-process vCPU quota scheduler.
    /// `None` ⇒ no quota (the pre-Plan-327 path).
    cpu_millicores: Option<u32>,
    /// Where to write the measured quota record on exit.
    /// `None` ⇒ no record is written.
    quota_record: Option<PathBuf>,
}

impl<'a> KernelBootUntilParams<'a> {
    pub fn builder(image: &'a [u8], timeout: Duration) -> KernelBootUntilParamsBuilder<'a> {
        KernelBootUntilParamsBuilder {
            kernel: KernelImageSource::Bytes(image),
            initramfs: None,
            disks: Vec::new(),
            vsock: false,
            timeout,
            stop: &NEVER_STOP,
            paused: &NEVER_PAUSE,
            channels: HostChannels::default(),
            cpu_millicores: None,
            quota_record: None,
        }
    }

    pub fn builder_file(kernel: &'a Path, timeout: Duration) -> KernelBootUntilParamsBuilder<'a> {
        KernelBootUntilParamsBuilder {
            kernel: KernelImageSource::File(kernel),
            initramfs: None,
            disks: Vec::new(),
            vsock: false,
            timeout,
            stop: &NEVER_STOP,
            paused: &NEVER_PAUSE,
            channels: HostChannels::default(),
            cpu_millicores: None,
            quota_record: None,
        }
    }
}

pub struct KernelBootUntilParamsBuilder<'a> {
    kernel: KernelImageSource<'a>,
    initramfs: Option<&'a [u8]>,
    disks: Vec<DiskImage>,
    vsock: bool,
    timeout: Duration,
    stop: &'static AtomicBool,
    paused: &'static AtomicBool,
    channels: HostChannels,
    cpu_millicores: Option<u32>,
    quota_record: Option<PathBuf>,
}

impl<'a> KernelBootUntilParamsBuilder<'a> {
    pub fn initramfs(mut self, initramfs: Option<&'a [u8]>) -> Self {
        self.initramfs = initramfs;
        self
    }

    pub fn disks(mut self, disks: Vec<DiskImage>) -> Self {
        self.disks = disks;
        self
    }

    pub fn vsock(mut self, vsock: bool) -> Self {
        self.vsock = vsock;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn stop(mut self, stop: &'static AtomicBool) -> Self {
        self.stop = stop;
        self
    }

    pub fn paused(mut self, paused: &'static AtomicBool) -> Self {
        self.paused = paused;
        self
    }

    pub fn channels(mut self, channels: HostChannels) -> Self {
        self.channels = channels;
        self
    }

    pub fn cpu_millicores(mut self, cpu_millicores: Option<u32>) -> Self {
        self.cpu_millicores = cpu_millicores;
        self
    }

    pub fn quota_record(mut self, quota_record: Option<PathBuf>) -> Self {
        self.quota_record = quota_record;
        self
    }

    pub fn build(self) -> KernelBootUntilParams<'a> {
        KernelBootUntilParams {
            kernel: self.kernel,
            initramfs: self.initramfs,
            disks: self.disks,
            vsock: self.vsock,
            timeout: self.timeout,
            stop: self.stop,
            paused: self.paused,
            channels: self.channels,
            cpu_millicores: self.cpu_millicores,
            quota_record: self.quota_record,
        }
    }
}

/// Boot `image` (an arm64 `Image`) under HVF, optionally with an `initramfs`
/// (cpio, gzip-or-raw), returning what it printed within `timeout`.
pub fn boot_kernel(
    image: &[u8],
    initramfs: Option<&[u8]>,
    disks: Vec<DiskImage>,
    vsock: bool,
    timeout: Duration,
) -> Result<KernelBootResult, HvfError> {
    boot_kernel_impl(
        KernelBootUntilParams::builder(image, timeout)
            .initramfs(initramfs)
            .disks(disks)
            .vsock(vsock)
            .build(),
    )
}

/// Like [`boot_kernel`], but stops as soon as `stop` is set — a
/// persistent-until-stop VM — and drives egress + the agent/substitution channels
/// through the caller-supplied [`HostChannels`] (the supervisor builds them from
/// the admitted plan + per-VM socket paths). The supervisor sets `stop` from a
/// SIGTERM handler so `HvfBackend::stop` ends the guest cleanly. Setting `paused`
/// parks the vCPU out of guest execution (RAM + devices intact) until it clears
/// again — the supervisor drives it from its SIGUSR1/SIGUSR2 handlers so
/// `HvfBackend::pause`/`resume` freeze and thaw the guest in place. `timeout`
/// still caps the run.
pub fn boot_kernel_until(params: KernelBootUntilParams<'_>) -> Result<KernelBootResult, HvfError> {
    boot_kernel_impl(params)
}

#[derive(Clone, Copy)]
enum KernelImageSource<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelImageMeta {
    file_len: usize,
    reserved_len: usize,
}

impl KernelImageMeta {
    fn new(file_len: usize, image_size: u64, file_backed: bool) -> Result<Self, HvfError> {
        let image_size =
            usize::try_from(image_size).map_err(|_| HvfError::BadBoot(BootFault::Overflow))?;
        let mapped_len = if file_backed {
            page_rounded_len(file_len)?
        } else {
            file_len
        };
        Ok(Self {
            file_len,
            reserved_len: mapped_len.max(image_size),
        })
    }
}

impl KernelImageSource<'_> {
    fn metadata(self) -> Result<KernelImageMeta, HvfError> {
        match self {
            Self::Bytes(image) => {
                let hdr = kernel_image::parse(image)
                    .map_err(|_| HvfError::BadBoot(BootFault::KernelNotArm64Image))?;
                KernelImageMeta::new(image.len(), hdr.image_size, false)
            }
            Self::File(path) => {
                let mut file = File::open(path)
                    .map_err(|e| HvfError::BadBoot(BootFault::KernelOpen(e.kind())))?;
                let mut header = [0_u8; 64];
                file.read_exact(&mut header)
                    .map_err(|e| HvfError::BadBoot(BootFault::KernelRead(e.kind())))?;
                let hdr = kernel_image::parse(&header)
                    .map_err(|_| HvfError::BadBoot(BootFault::KernelNotArm64Image))?;
                let len = file
                    .metadata()
                    .map_err(|e| HvfError::BadBoot(BootFault::KernelOpen(e.kind())))?
                    .len()
                    .try_into()
                    .map_err(|_| HvfError::BadBoot(BootFault::Overflow))?;
                KernelImageMeta::new(len, hdr.image_size, true)
            }
        }
    }

    fn load_into(self, ram: &mut GuestRam, offset: usize) -> Result<(), HvfError> {
        match self {
            Self::Bytes(image) => ram.copy_at(offset, image),
            Self::File(path) => {
                let meta = self.metadata()?;
                ram.map_private_file_at(offset, path, meta.file_len)
            }
        }
    }
}

fn initrd_load_offset(
    kernel_end: usize,
    initrd_len: usize,
    dtb_offset: usize,
) -> Result<usize, HvfError> {
    let preferred = PREFERRED_INITRD_OFFSET as usize;
    if preferred >= kernel_end
        && preferred
            .checked_add(initrd_len)
            .is_some_and(|end| end <= dtb_offset)
    {
        return Ok(preferred);
    }

    let fallback = kernel_end
        .checked_add(INITRD_ALIGNMENT - 1)
        .map(|value| value / INITRD_ALIGNMENT * INITRD_ALIGNMENT)
        .ok_or(HvfError::BadBoot(BootFault::Overflow))?;
    if fallback
        .checked_add(initrd_len)
        .is_some_and(|end| end <= dtb_offset)
    {
        Ok(fallback)
    } else {
        Err(HvfError::BadBoot(BootFault::InitrdNoRoom {
            kernel_end,
            initrd_len,
            dtb_offset,
        }))
    }
}

fn boot_kernel_impl(params: KernelBootUntilParams<'_>) -> Result<KernelBootResult, HvfError> {
    let KernelBootUntilParams {
        kernel,
        initramfs,
        disks,
        vsock,
        timeout,
        stop,
        paused,
        channels,
        cpu_millicores,
        quota_record,
    } = params;
    if disks.len() > MAX_DISKS {
        return Err(HvfError::BadBoot(BootFault::TooManyDisks {
            given: disks.len(),
            max: MAX_DISKS,
        }));
    }
    // Validate it's an arm64 Image; we load at the fixed boot-protocol offset.
    let kernel_meta = kernel.metadata()?;
    let ram_size = ram_size_bytes(channels.mem_mib);
    let load_off = KERNEL_LOAD_OFFSET as usize;
    let dtb_off = ram_size
        .checked_sub(FDT_MAX_SIZE as usize)
        .ok_or(HvfError::BadBoot(BootFault::GuestRamTooSmall {
            ram: ram_size,
            needed: FDT_MAX_SIZE as usize,
        }))?; // DTB window at top of RAM
    let kernel_end = load_off
        .checked_add(kernel_meta.reserved_len)
        .ok_or(HvfError::BadBoot(BootFault::Overflow))?;
    if kernel_end > dtb_off {
        return Err(HvfError::BadBoot(BootFault::KernelTooLarge {
            needed: kernel_end,
            available: dtb_off,
        }));
    }
    // Keep the stable 256 MiB placement when it fits, but support constrained
    // guests by placing the initramfs immediately after the kernel.
    let initrd_off = initramfs.map_or(Ok(PREFERRED_INITRD_OFFSET as usize), |rd| {
        initrd_load_offset(kernel_end, rd.len(), dtb_off)
    })?;

    // Demand-zero anonymous mapping: host pages fault in as the guest touches
    // them, so idle residency tracks the working set instead of `ram_size`.
    // `guest_ram` owns the region and unmaps it on drop, after `hv_vm_destroy`.
    let mut guest_ram = GuestRam::new(ram_size)?;
    let restore_mapping_micros = if let Some(path) = channels.restore_ram.as_deref() {
        let started = Instant::now();
        guest_ram.map_private_file(path)?;
        Some(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX))
    } else {
        None
    };
    let ram = guest_ram.as_ptr();

    // Base cmdline, plus optional appended args. Precedence: the `MVM_HVF_BOOTARGS`
    // dev override wins, then the caller-supplied cmdline (the builder rootfs needs
    // `init=/sbin/mvm-host-vm-init`, not the workload `init=/init`), then the
    // built-in default. The append hook lets a caller thread runtime-discovered
    // values (e.g. a dynamically bound egress target) on top without reproducing
    // the whole base.
    let mut bootargs = std::env::var("MVM_HVF_BOOTARGS")
        .ok()
        .or_else(|| channels.cmdline.clone())
        .unwrap_or_else(|| {
            if channels.virtiofs_root.is_some() {
                default_virtiofs_bootargs()
            } else {
                default_bootargs(!disks.is_empty())
            }
        });
    if let Ok(extra) = std::env::var("MVM_HVF_BOOTARGS_EXTRA") {
        let extra = extra.trim();
        if !extra.is_empty() {
            bootargs.push(' ');
            bootargs.push_str(extra);
        }
    }
    let initrd_bounds = initramfs.map(|rd| {
        (
            RAM_BASE + initrd_off as u64,
            RAM_BASE + initrd_off as u64 + rd.len() as u64,
        )
    });
    let mut virtio_nodes: Vec<(u64, u32)> = Vec::new();
    for i in 0..disks.len() {
        virtio_nodes.push(disk_mmio(i));
    }
    if vsock {
        virtio_nodes.push((VSOCK_MMIO_BASE, VSOCK_IRQ));
    }
    let has_virtiofs_root = channels.virtiofs_root.is_some();
    let fs_count = usize::from(has_virtiofs_root) + channels.virtiofs_shares.len();
    if fs_count > MAX_VIRTIOFS_SHARES + 1 {
        return Err(HvfError::BadBoot(BootFault::TooManyFilesystems {
            given: fs_count,
            max: MAX_VIRTIOFS_SHARES + 1,
        }));
    }
    for index in 0..fs_count {
        virtio_nodes.push((
            FS_MMIO_BASE + index as u64 * MMIO_STRIDE,
            FS_IRQ + index as u32,
        ));
    }
    virtio_nodes.push((RNG_MMIO_BASE, RNG_IRQ));
    // Fresh host entropy per boot covers the window before the virtio-rng driver
    // probes. The device below then replenishes entropy for the VM's lifetime.
    let rng_seed = fdt::fresh_rng_seed();
    let dtb = fdt::build_dtb(
        &bootargs,
        RAM_BASE,
        ram_size as u64,
        initrd_bounds,
        &virtio_nodes,
        Some(&rng_seed),
        // One, until the count reaches this process. `HvfSupervisorConfig`
        // carries no `vcpus` field yet, so there is nothing truthful to pass —
        // describing CPUs in the tree that no `hv_vcpu_create` backs would hang
        // the guest waiting for secondaries that never arrive. Step 1 of #2888
        // adds the field; this becomes `cfg.vcpus` then.
        1,
    );
    if dtb.len() > FDT_MAX_SIZE as usize {
        return Err(HvfError::BadBoot(BootFault::DtbTooLarge {
            needed: dtb.len(),
            max: FDT_MAX_SIZE as usize,
        }));
    }

    if channels.restore_frame.is_none() {
        kernel.load_into(&mut guest_ram, load_off)?;
        guest_ram.copy_at(dtb_off, &dtb)?;
        if let Some(rd) = initramfs {
            guest_ram.copy_at(initrd_off, rd)?;
        }
    }

    let entry = RAM_BASE + KERNEL_LOAD_OFFSET;
    let dtb_addr = RAM_BASE + dtb_off as u64;

    // SAFETY: VM created before use and destroyed before `ram` is freed.
    let result = unsafe {
        let rc = hv_vm_create(core::ptr::null_mut());
        if rc != HV_SUCCESS {
            return Err(HvfError::VmCreate(rc));
        }
        let mapped_ram_size = guest_ram.len();
        let mut r = run(
            &mut guest_ram,
            ram,
            entry,
            dtb_addr,
            RunInputs {
                disks,
                vsock,
                timeout,
                ram_size: mapped_ram_size,
                agent_socket: channels.agent_socket,
                substitution_socket: channels.substitution_socket,
                egress_relay: channels.egress_relay,
                trusted_builder_egress: channels.trusted_builder_egress,
                broker_socket: channels.broker_socket,
                console_data_sockets: channels.console_data_sockets,
                builder_control_sockets: channels.builder_control_sockets,
                virtiofs_root: channels.virtiofs_root,
                virtiofs_shares: channels.virtiofs_shares,
                console_log: channels.console_log,
                pause_state: channels.pause_state,
                snapshot_request: channels.snapshot_request,
                snapshot_ram: channels.snapshot_ram,
                snapshot_frame: channels.snapshot_frame,
                restore_ram: channels.restore_ram,
                restore_frame: channels.restore_frame,
                handoff_socket: channels.handoff_socket,
                handoff_root: channels.handoff_root,
                handoff_verify_key: channels.handoff_verify_key,
                cpu_millicores,
                quota_record,
            },
            stop,
            paused,
        );
        let vm_destroy_started = Instant::now();
        hv_vm_destroy();
        if let Ok(result) = &mut r
            && let Some(timing) = &mut result.shutdown_timing
        {
            timing.vm_destroy = vm_destroy_started.elapsed();
        }
        r
    };
    // `guest_ram` unmaps here as it drops, after `hv_vm_destroy` above.
    result.map(|mut boot_result| {
        boot_result.restore_mapping_micros = restore_mapping_micros;
        boot_result
    })
}

/// # Safety
/// Between `hv_vm_create`/`hv_vm_destroy`; `ram` holds RAM_SIZE bytes with the
/// kernel + DTB loaded.
/// Device + run inputs for [`run`], bundled to keep its argument count sane.
struct RunInputs {
    disks: Vec<DiskImage>,
    vsock: bool,
    timeout: Duration,
    /// Mapped guest RAM size in bytes (matches the host allocation).
    ram_size: usize,
    /// Per-VM agent RPC socket (productionized off `MVM_HVF_AGENT_SOCKET`).
    agent_socket: Option<PathBuf>,
    /// Per-VM substitution-endpoint socket (productionized off
    /// `MVM_HVF_SUBSTITUTION_SOCKET`).
    substitution_socket: Option<PathBuf>,
    /// Per-VM egress bridge UDS. When set, `EGRESS_PORT` relays here — the
    /// endpoint is the sole gate + substituter.
    egress_relay: Option<PathBuf>,
    /// Trusted-builder tier: relay egress without the per-workload byte-rate cap.
    trusted_builder_egress: bool,
    /// Per-VM host-services broker UDS. When set, `BROKER_PORT` relays here — the
    /// socket the host-agent daemon bound for this VM.
    broker_socket: Option<PathBuf>,
    /// Dev-only host console listeners (one `(guest_port, host_socket)` per console
    /// data port). Empty for a sealed prod config — nothing bound (claim 15).
    console_data_sockets: Vec<(u32, PathBuf)>,
    builder_control_sockets: Vec<(u32, PathBuf)>,
    /// When set, serve this host dir to the guest as a read-only virtiofs root.
    virtiofs_root: Option<PathBuf>,
    virtiofs_shares: Vec<(String, PathBuf)>,
    /// Host console log the PL011 mirrors guest output into as it arrives.
    console_log: Option<PathBuf>,
    pause_state: Option<PathBuf>,
    snapshot_request: Option<PathBuf>,
    snapshot_ram: Option<PathBuf>,
    snapshot_frame: Option<PathBuf>,
    restore_ram: Option<PathBuf>,
    restore_frame: Option<PathBuf>,
    handoff_socket: Option<PathBuf>,
    handoff_root: Option<PathBuf>,
    handoff_verify_key: Option<String>,
    /// CPU share to enforce via the in-process vCPU quota scheduler.
    cpu_millicores: Option<u32>,
    /// Where to write the measured quota record on exit.
    quota_record: Option<PathBuf>,
}

unsafe fn run(
    guest_ram: &mut GuestRam,
    ram: *mut u8,
    entry: u64,
    dtb_addr: u64,
    inputs: RunInputs,
    stop: &'static AtomicBool,
    paused: &'static AtomicBool,
) -> Result<KernelBootResult, HvfError> {
    let RunInputs {
        disks,
        vsock,
        timeout,
        ram_size,
        agent_socket,
        substitution_socket,
        egress_relay,
        trusted_builder_egress,
        broker_socket,
        console_data_sockets,
        builder_control_sockets,
        virtiofs_root,
        virtiofs_shares,
        console_log,
        pause_state,
        snapshot_request,
        snapshot_ram,
        snapshot_frame,
        restore_ram: _restore_ram,
        restore_frame,
        handoff_socket,
        handoff_root,
        handoff_verify_key,
        cpu_millicores,
        quota_record,
    } = inputs;
    unsafe {
        // In-kernel GICv3 — created after the VM, before any vCPU. Base
        // addresses must match the DTB's intc node, or the kernel's IRQ/timer
        // init hangs (no console).
        let gic_cfg = hv_gic_config_create();
        let grc = hv_gic_config_set_distributor_base(gic_cfg, fdt::GICV3_DIST_BASE);
        let grc = if grc == HV_SUCCESS {
            hv_gic_config_set_redistributor_base(gic_cfg, fdt::GICV3_REDIST_BASE)
        } else {
            grc
        };
        let grc = if grc == HV_SUCCESS {
            hv_gic_create(gic_cfg)
        } else {
            grc
        };
        if grc != HV_SUCCESS {
            return Err(HvfError::GicCreate(grc));
        }

        let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
        let rc = hv_vm_map(ram.cast(), RAM_BASE, ram_size, flags);
        if rc != HV_SUCCESS {
            return Err(HvfError::Map(rc));
        }

        let mut vcpu_id: hv_vcpu_t = 0;
        let mut exit: *mut hv_vcpu_exit_t = core::ptr::null_mut();
        let rc = hv_vcpu_create(&mut vcpu_id, &mut exit, core::ptr::null_mut());
        if rc != HV_SUCCESS {
            return Err(HvfError::VcpuCreate(rc));
        }
        // Wrap the raw vCPU in the seam type and drive it through the unified run
        // loop (crate::vmm::run) — the same body the KVM backend uses.
        let vcpu = HvfVcpu::from_raw(vcpu_id, exit);

        // MPIDR_EL1 affinity 0 must match FDT cpu@0 + the GIC redistributor frame
        // (else gic_populate_rdist walks off the region and faults). arm64 boot
        // protocol: x0=DTB, x1..x3=0, PC=entry, EL1h with DAIF masked.
        let setup = vcpu
            .set_sys(SysReg::MpidrEl1, 0)
            .and_then(|()| vcpu.set_core(CoreReg::Pc, entry))
            .and_then(|()| vcpu.set_core(CoreReg::Cpsr, 0x3c5))
            .and_then(|()| vcpu.set_core(CoreReg::X(0), dtb_addr))
            .and_then(|()| vcpu.set_core(CoreReg::X(1), 0))
            .and_then(|()| vcpu.set_core(CoreReg::X(2), 0))
            .and_then(|()| vcpu.set_core(CoreReg::X(3), 0));
        if let Err(e) = setup {
            hv_vcpu_destroy(vcpu_id);
            return Err(e);
        }

        // Watchdog + heartbeat: a booting kernel never exits on its own, so force
        // the vCPU out after `timeout` or as soon as `stop` is set (graceful stop).
        // Between those, a periodic force-exit acts as a heartbeat: it breaks the
        // guest out of WFI so the run loop can poll host-side async work (drain an
        // egress socket into a guest blocked in `recv`). The run loop
        // treats a forced exit as a stop only when `stop` is set, so a heartbeat
        // wake just polls and continues. On timeout we set `stop` first so the run
        // loop ends.
        let done = Arc::new(AtomicBool::new(false));
        let done_w = done.clone();
        // Open-egress-connection count, shared with the vsock device. The heartbeat
        // only fires while this is non-zero — a guest with no open egress socket has
        // no host push to wait for, so the host can idle instead of waking 200×/s.
        let egress_active = Arc::new(AtomicUsize::new(0));
        let egress_active_w = egress_active.clone();
        let pause_ack = Arc::new(AtomicBool::new(false));
        let pause_ack_w = Arc::clone(&pause_ack);
        let pause_state_w = pause_state.clone();
        // Host agent listener path (host→guest RPC, GUEST_AGENT_PORT). When bound,
        // the heartbeat fires unconditionally so the run loop polls the listener +
        // services agent streams even while the guest is idle in WFI — an agent VM
        // exists to answer host RPC, so the wake is warranted. (A transient
        // run-to-exit VM leaves this unset and keeps the egress-gated heartbeat.)
        // Per-VM socket paths come from the supervisor config; fall back to the
        // dev/live env hooks when the config omits them (the example drivers).
        let agent_socket =
            agent_socket.or_else(|| std::env::var_os("MVM_HVF_AGENT_SOCKET").map(PathBuf::from));
        let agent_bound = agent_socket.is_some();
        let substitution_socket = substitution_socket
            .or_else(|| std::env::var_os("MVM_HVF_SUBSTITUTION_SOCKET").map(PathBuf::from));
        let handle = vcpu.exit_token();

        // Start the in-process CPU quota controller when the supervisor config
        // carries a share. Failing to start the controller must not fail the
        // boot; the VM falls back to the unbounded path and writes no record.
        let mut quota: Option<VcpuQuota<HvfHandle>> = None;
        if let Some(millicores) = cpu_millicores
            && let Ok(config) = QuotaConfig::for_share(millicores)
            && let Ok(clock) = ThreadCpuHandle::for_current_thread()
        {
            quota = Some(VcpuQuota::start(handle, clock, QuotaPolicy::new(config)));
        }
        let throttle_flag = quota
            .as_ref()
            .map(|q| q.throttle_flag().clone())
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

        let watchdog = std::thread::spawn(move || {
            let step = Duration::from_millis(5);
            let mut waited = Duration::ZERO;
            let stop_observed_at = loop {
                std::thread::sleep(step);
                if done_w.load(Ordering::Relaxed) {
                    if let Some(path) = &pause_state_w {
                        let _ = std::fs::remove_file(path);
                    }
                    return None; // run already ended; don't poke a finishing vCPU
                }
                if stop.load(Ordering::Relaxed) {
                    break Instant::now(); // requested stop / workload-exit
                }
                waited += step;
                if waited >= timeout {
                    stop.store(true, Ordering::Relaxed); // timeout → end the run
                    break Instant::now();
                }
                // Break the guest out of `hv_vcpu_run` when: a pause was requested
                // (so the run loop reaches its pause hold and parks the vCPU), an
                // agent listener is bound (accept/serve RPC), or there's host→guest
                // egress to deliver. An idle transient VM gets no heartbeat, so the
                // explicit paused check is what parks it; while it sits in the hold
                // the extra nudges are harmless (it is out of guest execution).
                if paused.load(Ordering::Relaxed)
                    || agent_bound
                    || egress_active_w.load(Ordering::Relaxed) > 0
                {
                    HvfHandle::force_exit(&[handle]); // wake the run loop
                }
            };
            pause_ack_w.store(false, Ordering::Release);
            if let Some(path) = &pause_state_w {
                let _ = std::fs::remove_file(path);
            }
            HvfHandle::force_exit(&[handle]); // final wake → loop sees stop, returns
            Some(stop_observed_at)
        });

        let mut uart = Pl011::new(UART_BASE);
        // Mirror guest output to the host log as it arrives. Write-only, and
        // best-effort: a console log that cannot be opened costs a diagnostic,
        // never the boot. The full transcript still comes back in the result.
        if let Some(path) = console_log.as_deref()
            && let Ok(file) = mvm_vmm::host::console_capture::open_console_capture(path)
        {
            uart.stream_to(Box::new(file));
        }
        // One virtio-blk per disk image (`/dev/vda`, `/dev/vdb`, …) at its window.
        let mut virtio_disks: Vec<VirtioBlk> = disks
            .into_iter()
            .enumerate()
            .map(|(i, img)| {
                let (base, irq) = disk_mmio(i);
                // SAFETY: `ram` is the mapped guest RAM, valid for the run (this
                // whole fn body is already within an `unsafe` block).
                VirtioBlk::new(base, irq, ram, RAM_BASE, ram_size, img)
            })
            .collect();
        let mut vsock_dev =
            vsock.then(|| VirtioVsock::new(VSOCK_MMIO_BASE, VSOCK_IRQ, ram, RAM_BASE, ram_size));
        // virtiofs-root dev boot: serve the unpacked+injected tree read-only.
        let has_virtiofs_root = virtiofs_root.is_some();
        let mut fs_devs =
            Vec::with_capacity(usize::from(has_virtiofs_root) + virtiofs_shares.len());
        if let Some(root) = virtiofs_root {
            // SAFETY: `ram` is the mapped guest RAM valid for the run (this fn body
            // is within an `unsafe` block), same contract as the other devices.
            fs_devs.push(VirtioFs::new(
                FS_MMIO_BASE,
                FS_IRQ,
                ram,
                RAM_BASE,
                ram_size,
                root,
            ));
        }
        for (index, (tag, root)) in virtiofs_shares.into_iter().enumerate() {
            fs_devs.push(VirtioFs::with_tag(
                FS_MMIO_BASE + (index + usize::from(has_virtiofs_root)) as u64 * MMIO_STRIDE,
                FS_IRQ + (index + usize::from(has_virtiofs_root)) as u32,
                ram,
                RAM_BASE,
                ram_size,
                root,
                tag,
            ));
        }
        // SAFETY: `ram` is the mapped guest RAM valid for the run. The device
        // retains no generated bytes, so restored guests continue from fresh OS
        // entropy rather than replaying device-owned state.
        let mut rng_dev = VirtioRng::new(RNG_MMIO_BASE, RNG_IRQ, ram, RAM_BASE, ram_size);
        if restore_frame.is_none()
            && let Some(v) = vsock_dev.as_mut()
        {
            // Transient run-to-exit: a guest write of the exit code to the workload
            // exit port stops the run (VM life = workload life) — but ONLY when this
            // is not an agent-serving VM. An agent VM binds the agent socket; its
            // baked `/init` reports a workload-exit the instant it finds no
            // per-call entrypoint, yet the agent keeps serving. Tearing the VM down
            // on that early signal would kill the agent before a host RPC (e.g.
            // `machine invoke`) can reach it. Persistent agent VMs are ended by the
            // supervisor's SIGTERM/timeout instead. The exit code is still recorded
            // for reporting either way.
            if !agent_bound {
                v.capture_workload_exit(stop);
            }
            // Host→guest agent RPC (GUEST_AGENT_PORT): expose the listener so host
            // clients (`machine invoke`) reach the guest agent over vsock.
            if let Some(path) = &agent_socket {
                v.set_agent_activity(egress_active.clone());
                if let Err(e) = v.set_agent_socket(path) {
                    eprintln!(
                        "mvm-hvf: agent socket bind failed at {}: {e}",
                        path.display()
                    );
                }
            }
            // Egress routing for EGRESS_PORT: a pure relay to the per-VM endpoint,
            // which owns the whole egress decision (claim-10 default-deny + secret
            // substitution). The relay UDS comes from the supervisor config; fall
            // back to the dev/live `MVM_HVF_SUBSTITUTION_SOCKET` hook. Shares the
            // heartbeat counter so an in-flight request awaiting its reply keeps the
            // loop polling. With no relay wired, EGRESS_PORT fails closed at the
            // bridge — the admitted-runtime case for a deny-all workload carrying
            // no bound secrets, which spawns no endpoint and has no egress path.
            if let Some(relay) = egress_relay.as_ref().or(substitution_socket.as_ref()) {
                v.set_substitution_activity(egress_active.clone());
                v.set_network_endpoint(relay);
            }
            if trusted_builder_egress {
                v.set_trusted_builder_egress();
            }
            // Host-services broker (BROKER_PORT): a pure relay to the per-VM broker
            // UDS the host-agent daemon bound, so a guest `host.audit.v1` call
            // reaches the broker. Shares the heartbeat counter so an in-flight
            // request awaiting its reply keeps the loop polling. With no broker
            // socket wired, BROKER_PORT fails closed at the bridge.
            if let Some(broker) = broker_socket.as_ref() {
                v.set_broker_activity(egress_active.clone());
                v.set_broker_endpoint(broker);
            }
            // Dev-only interactive console (`machine run -it`): bind one host
            // listener per guest console data port so the console driver can reach
            // the agent-allocated PTY channel. The list is populated only for a
            // `dev_console` machine; a sealed prod config carries none, so nothing
            // is bound (claim 15). Shares the heartbeat counter so an open console
            // stream keeps the loop waking an idle guest.
            // Builder control ports ride the same bridge, and a persistent
            // builder has no console, so bind whichever list is populated.
            // They cannot both be: one is dev-console policy, the other
            // builder-tier policy.
            let host_dial_sockets: Vec<(u32, PathBuf)> = console_data_sockets
                .iter()
                .chain(builder_control_sockets.iter())
                .cloned()
                .collect();
            if !host_dial_sockets.is_empty() {
                v.set_host_dial_activity(egress_active.clone());
                let ports = host_dial_sockets
                    .iter()
                    .map(|(port, path)| (*port, path.as_path()));
                if let Err(e) = v.set_host_dial_sockets(ports) {
                    eprintln!("mvm-hvf: host-dial socket bind failed: {e}");
                }
            }
            if v.set_handoff_control(
                handoff_socket.as_deref(),
                handoff_root.as_deref(),
                handoff_verify_key.as_deref(),
                stop,
            )
            .is_err()
            {
                return Err(HvfError::SnapshotState("handoff control setup failed"));
            }
            // Start the dedicated host-I/O thread now that the agent/egress/console
            // sockets are wired: it services host→guest delivery on wall-clock time
            // and raises the guest IRQ itself, so reachability no longer depends on
            // the starved vCPU `poll()` path. Joined in `shutdown()` below before RAM
            // is freed.
            v.start_io(Arc::new(GicSpi));
        }

        // Diagnostics gathered by the exception hook (HVC/PSCI + other traps).
        let mut hvc_calls = 0usize;
        let mut other_exceptions = 0usize;
        let mut psci_fns: Vec<u64> = Vec::new();
        let mut other_ecs: Vec<u32> = Vec::new();

        if let Some(frame_path) = restore_frame.as_deref() {
            let frame = std::fs::read(frame_path)
                .map_err(|_| HvfError::SnapshotState("restore frame read failed"))?;
            let mut restore_devices: Vec<&mut dyn RunDevice> = vec![&mut uart];
            for device in &mut virtio_disks {
                restore_devices.push(device);
            }
            if let Some(device) = vsock_dev.as_mut() {
                restore_devices.push(device);
            }
            for device in &mut fs_devs {
                restore_devices.push(device);
            }
            restore_devices.push(&mut rng_dev);
            let mut snapshot_targets = restore_devices
                .iter_mut()
                .filter_map(|device| device.snapshot_device_mut())
                .collect::<Vec<_>>();
            super::snapshot::restore_hvf_snapshot_control(
                &frame,
                guest_ram.len(),
                &vcpu,
                &mut snapshot_targets,
            )
            .map_err(|_| HvfError::SnapshotState("restore control state failed"))?;
            drop(snapshot_targets);
            drop(restore_devices);

            if let Some(v) = vsock_dev.as_mut() {
                if !agent_bound {
                    v.capture_workload_exit(stop);
                }
                v.set_agent_activity(egress_active.clone());
                v.set_substitution_activity(egress_active.clone());
                v.set_broker_activity(egress_active.clone());
                v.set_host_dial_activity(egress_active.clone());
                let bindings = crate::vmm::vsock::VsockHostBindings {
                    agent_socket: agent_socket.clone(),
                    network_endpoint: egress_relay.clone().or_else(|| substitution_socket.clone()),
                    broker_endpoint: broker_socket.clone(),
                    console_sockets: console_data_sockets.clone(),
                };
                v.rebind_host_channels(&bindings, Arc::new(GicSpi))
                    .map_err(|_| HvfError::SnapshotState("restore channel rebind failed"))?;
                if trusted_builder_egress {
                    v.set_trusted_builder_egress();
                }
            }
        }

        // Scope the device list so its mutable borrows end before we read the
        // device output below.
        let outcome = {
            let mut devices: Vec<&mut dyn RunDevice> = vec![&mut uart];
            for v in virtio_disks.iter_mut() {
                devices.push(v);
            }
            if let Some(v) = vsock_dev.as_mut() {
                devices.push(v);
            }
            for fs in &mut fs_devs {
                devices.push(fs);
            }
            devices.push(&mut rng_dev);
            let set_irq = |intid: u32, level: bool| -> Result<(), HvfError> {
                // SAFETY: FFI to the process-global in-kernel GIC (nested in the
                // enclosing `unsafe` block).
                if hv_gic_set_spi(intid, level) == HV_SUCCESS {
                    Ok(())
                } else {
                    Err(HvfError::GicCreate(0))
                }
            };
            let snapshot_guest_ram = &*guest_ram;
            run::run_with_hooks(
                &vcpu,
                set_irq,
                &mut devices,
                run::RunHooks {
                    on_exception: |vc: &HvfVcpu, esr, _phys| {
                        if esr_ec(esr) == EC_HVC_AARCH64 {
                            hvc_calls += 1;
                            let fn_id = vc.get_core(CoreReg::X(0))?;
                            if psci_fns.len() < 16 && !psci_fns.contains(&fn_id) {
                                psci_fns.push(fn_id);
                            }
                            match fn_id {
                                PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => return Ok(RunControl::Stop),
                                PSCI_VERSION_FN => vc.set_core(CoreReg::X(0), 0x1_0000)?, // PSCI v1.0
                                _ => vc.set_core(CoreReg::X(0), PSCI_NOT_SUPPORTED)?,
                            }
                            // HVC is completed: HVF already advanced PC. Do NOT advance.
                            Ok(RunControl::Continue)
                        } else {
                            let ec = esr_ec(esr);
                            other_exceptions += 1;
                            if other_ecs.len() < 16 && !other_ecs.contains(&ec) {
                                other_ecs.push(ec);
                            }
                            // Advance past the faulting instruction and keep going.
                            let pc = vc.get_core(CoreReg::Pc)?;
                            vc.set_core(CoreReg::Pc, pc + 4)?;
                            Ok(RunControl::Continue)
                        }
                    },
                    // A forced exit is a real stop only when `stop` is set (timeout or
                    // graceful); otherwise it's a heartbeat wake so the run loop can drain
                    // egress sockets into a guest blocked in WFI (vsock-only egress async proxy).
                    should_stop: move || stop.load(Ordering::Relaxed),
                    // Park the vCPU in the run loop's pause hold while `paused` is set,
                    // freezing guest RAM + device state in place until resume clears it.
                    should_pause: move || {
                        let requested = paused.load(Ordering::Relaxed);
                        if requested {
                            if !pause_ack.swap(true, Ordering::AcqRel)
                                && let Some(path) = &pause_state
                            {
                                let _ = std::fs::write(path, b"paused\n");
                            }
                        } else if pause_ack.swap(false, Ordering::AcqRel)
                            && let Some(path) = &pause_state
                        {
                            let _ = std::fs::remove_file(path);
                        }
                        requested
                    },
                    on_pause: move |vcpu, devices| {
                        let (Some(request_path), Some(ram_path), Some(frame_path)) = (
                            snapshot_request.as_deref(),
                            snapshot_ram.as_deref(),
                            snapshot_frame.as_deref(),
                        ) else {
                            return Ok(());
                        };
                        if !request_path.exists() {
                            return Ok(());
                        }
                        let ram_bytes = snapshot_guest_ram.snapshot_bytes();
                        let device_bytes = capture_device_states(devices).map_err(|_| {
                            HvfError::SnapshotState("snapshot device capture failed")
                        })?;
                        let vcpu_state = vcpu.capture_state()?;
                        let frame = super::snapshot::encode_hvf_snapshot_frame(
                            HVF_SNAPSHOT_BACKEND_KIND,
                            0,
                            &ram_bytes,
                            &device_bytes,
                            &vcpu_state,
                            &[],
                        )
                        .map_err(|_| HvfError::SnapshotState("snapshot frame encode failed"))?;
                        std::fs::write(ram_path, &ram_bytes)
                            .map_err(|_| HvfError::SnapshotState("snapshot RAM write failed"))?;
                        std::fs::write(frame_path, frame)
                            .map_err(|_| HvfError::SnapshotState("snapshot frame write failed"))?;
                        std::fs::remove_file(request_path).map_err(|_| {
                            HvfError::SnapshotState("snapshot request cleanup failed")
                        })?;
                        Ok(())
                    },
                    should_throttle: move || throttle_flag.load(Ordering::Relaxed),
                    _marker: std::marker::PhantomData,
                },
            )?
        };

        let vcpu_exited_at = Instant::now();
        done.store(true, Ordering::Relaxed);
        let watchdog_join_started = Instant::now();
        let stop_observed_at = watchdog.join().ok().flatten();
        let watchdog_join = watchdog_join_started.elapsed();

        // Stop the quota controller and persist the measured achievement. The
        // record is written before the vsock I/O thread joins so the file is
        // durable alongside the other VM outputs.
        if let Some(q) = quota.take() {
            let achievement = q.stop();
            if let Some(path) = &quota_record
                && let Some(parent) = path.parent()
            {
                let record = VcpuQuotaRecord {
                    target_millicores: achievement.target_millicores,
                    achieved_millicores: achievement.achieved_millicores,
                    period_ms: u32::try_from(achievement.period.as_millis()).unwrap_or(u32::MAX),
                    measured_wall_ms: u64::try_from(achievement.measured_wall.as_millis())
                        .unwrap_or(u64::MAX),
                    measured_cpu_ms: u64::try_from(achievement.measured_cpu.as_millis())
                        .unwrap_or(u64::MAX),
                    periods: achievement.periods,
                };
                let _ = mvm_core::vcpu_quota::write_record(parent, &record);
            }
        }

        // Join the vsock host-I/O thread before touching device state or freeing
        // the guest RAM it points into — the join is the memory-safety barrier.
        let io_thread_join_started = Instant::now();
        if let Some(v) = vsock_dev.as_mut() {
            v.shutdown();
        }
        let io_thread_join = io_thread_join_started.elapsed();
        let final_pc = vcpu.get_core(CoreReg::Pc).unwrap_or(0);
        let vcpu_destroy_started = Instant::now();
        hv_vcpu_destroy(vcpu_id);
        let vcpu_destroy = vcpu_destroy_started.elapsed();

        let mut r = KernelBootResult {
            console: uart.output,
            exit_reason: match outcome {
                RunOutcome::Canceled => HV_EXIT_REASON_CANCELED,
                _ => HV_EXIT_REASON_EXCEPTION,
            },
            hvc_calls,
            stopped_by_watchdog: outcome == RunOutcome::Canceled,
            other_exceptions,
            psci_fns,
            other_ecs,
            final_pc,
            shutdown_timing: stop_observed_at.map(|observed_at| KernelShutdownTiming {
                watchdog_to_vcpu_exit: vcpu_exited_at.saturating_duration_since(observed_at),
                watchdog_join,
                io_thread_join,
                vcpu_destroy,
                vm_destroy: Duration::ZERO,
            }),
            ..Default::default()
        };
        if let Some(vs) = &vsock_dev {
            r.vsock_received = vs.received();
            r.workload_exit_code = vs.workload_exit_code();
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            r.resident_ram_bytes = guest_ram.resident_bytes().ok();
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arm64_image(size: usize, image_size: u64) -> Vec<u8> {
        let mut image = vec![0_u8; size];
        image[8..16].copy_from_slice(&KERNEL_LOAD_OFFSET.to_le_bytes());
        image[16..24].copy_from_slice(&image_size.to_le_bytes());
        image[56..60].copy_from_slice(&0x644d_5241_u32.to_le_bytes());
        image
    }

    #[test]
    fn default_bootargs_mounts_rootfs_when_disk_present() {
        // A virtio-blk disk is a real mkGuest workload rootfs: mount it and run
        // the baked init, matching the read-only root-device contract
        // the other backends boot mkGuest images with.
        let with = default_bootargs(true);
        assert!(
            with.contains("root=/dev/vda ro"),
            "real workload must mount the virtio-blk rootfs: {with}"
        );
        assert!(
            with.contains("init=/init"),
            "must run the mkGuest init: {with}"
        );
        assert!(with.contains("console=ttyAMA0"), "console wired: {with}");

        // Disk-less boots (initramfs / freestanding demos) keep the demo args.
        let without = default_bootargs(false);
        assert!(
            !without.contains("root="),
            "disk-less boot must not mount a root: {without}"
        );
        assert!(
            without.contains("console=ttyAMA0"),
            "console wired: {without}"
        );
    }

    #[test]
    fn kernel_boot_result_marks_restore_measurement_as_optional() {
        let result = KernelBootResult::default();
        assert_eq!(result.restore_mapping_micros, None);
        assert_eq!(result.resident_ram_bytes, None);
        assert_eq!(result.shutdown_timing, None);
    }

    #[test]
    fn kernel_metadata_reserves_effective_image_size_tail() {
        let image = arm64_image(128, 4096);
        let meta = KernelImageSource::Bytes(&image).metadata().unwrap();
        assert_eq!(meta.file_len, 128);
        assert_eq!(meta.reserved_len, 4096);
    }

    #[test]
    fn kernel_metadata_uses_file_length_when_larger_than_header_size() {
        let image = arm64_image(4096, 128);
        let meta = KernelImageSource::Bytes(&image).metadata().unwrap();
        assert_eq!(meta.file_len, 4096);
        assert_eq!(meta.reserved_len, 4096);
    }

    #[test]
    fn initrd_uses_stable_offset_when_guest_ram_has_room() {
        assert_eq!(
            initrd_load_offset(10 * 1024 * 1024, 1024 * 1024, 510 * 1024 * 1024).unwrap(),
            PREFERRED_INITRD_OFFSET as usize
        );
    }

    #[test]
    fn initrd_falls_back_below_dtb_for_256_mib_guest() {
        let offset = initrd_load_offset(10 * 1024 * 1024, 1024 * 1024, 254 * 1024 * 1024).unwrap();

        assert_eq!(offset, 10 * 1024 * 1024);
        assert!(offset + 1024 * 1024 <= 254 * 1024 * 1024);
    }

    #[test]
    fn file_kernel_metadata_reads_header_without_loading_whole_image() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("Image");
        std::fs::write(&kernel, arm64_image(128, (HVF_PAGE_SIZE * 2) as u64)).unwrap();

        let meta = KernelImageSource::File(&kernel).metadata().unwrap();
        assert_eq!(meta.file_len, 128);
        assert_eq!(meta.reserved_len, HVF_PAGE_SIZE * 2);
    }

    #[test]
    fn file_kernel_metadata_reserves_page_rounded_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("Image");
        std::fs::write(&kernel, arm64_image(128, 0)).unwrap();

        let meta = KernelImageSource::File(&kernel).metadata().unwrap();
        assert_eq!(meta.file_len, 128);
        assert_eq!(meta.reserved_len, HVF_PAGE_SIZE);
    }

    #[test]
    fn sixth_disk_slot_stays_below_virtiofs_window() {
        let (last_mmio, _) = disk_mmio(MAX_DISKS - 1);
        assert!(
            last_mmio + MMIO_STRIDE <= FS_MMIO_BASE,
            "sixth disk must fit below the virtiofs MMIO window"
        );

        let (next_mmio, _) = disk_mmio(MAX_DISKS);
        assert_eq!(
            next_mmio, FS_MMIO_BASE,
            "a seventh disk would collide with the virtiofs root window"
        );
    }

    #[test]
    fn guest_ram_file_mapping_is_private_cow() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("Image");
        std::fs::write(&kernel, b"abcdefgh").unwrap();
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).unwrap();

        ram.copy_at(0, b"anon").unwrap();
        ram.map_private_file_at(HVF_PAGE_SIZE, &kernel, 8).unwrap();

        let mapped = unsafe { std::slice::from_raw_parts(ram.as_ptr().add(HVF_PAGE_SIZE), 8) };
        assert_eq!(mapped, b"abcdefgh");

        unsafe {
            *ram.as_ptr().add(HVF_PAGE_SIZE) = b'Z';
        }
        assert_eq!(std::fs::read(&kernel).unwrap(), b"abcdefgh");
        let mapped = unsafe { std::slice::from_raw_parts(ram.as_ptr().add(HVF_PAGE_SIZE), 8) };
        assert_eq!(mapped, b"Zbcdefgh");
    }

    /// The point of the split: the four things an operator can actually do
    /// something about must not print the same. Before this, a missing kernel,
    /// an empty one, a truncated one and one that is not an arm64 image were
    /// all `BadKernel` — the operator had to read the source and guess.
    #[test]
    fn each_kernel_failure_names_itself() {
        let dir = tempfile::tempdir().expect("tempdir");

        let missing = dir.path().join("not-here");
        assert_eq!(
            KernelImageSource::File(&missing).metadata(),
            Err(HvfError::BadBoot(BootFault::KernelOpen(
                std::io::ErrorKind::NotFound
            )))
        );

        // Zero bytes: the header read cannot be satisfied.
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").expect("write empty");
        assert!(matches!(
            KernelImageSource::File(&empty).metadata(),
            Err(HvfError::BadBoot(BootFault::KernelRead(_)))
        ));

        // A full header's worth of bytes that is not an arm64 Image.
        let garbage = dir.path().join("garbage");
        std::fs::write(&garbage, [0x5a_u8; 128]).expect("write garbage");
        assert_eq!(
            KernelImageSource::File(&garbage).metadata(),
            Err(HvfError::BadBoot(BootFault::KernelNotArm64Image))
        );

        // In-memory bytes take the same header check.
        assert_eq!(
            KernelImageSource::Bytes(&[0x5a_u8; 128]).metadata(),
            Err(HvfError::BadBoot(BootFault::KernelNotArm64Image))
        );
    }

    /// A zero-length mapping and an overflowing one are different faults, and
    /// `page_rounded_len` is where both are decided.
    #[test]
    fn page_rounding_separates_an_empty_image_from_an_overflowing_one() {
        assert_eq!(
            page_rounded_len(0),
            Err(HvfError::BadBoot(BootFault::KernelEmpty))
        );
        assert_eq!(
            page_rounded_len(usize::MAX),
            Err(HvfError::BadBoot(BootFault::Overflow))
        );
        assert_eq!(page_rounded_len(1), Ok(HVF_PAGE_SIZE));
    }

    /// The initramfs placement failure carries the three numbers needed to see
    /// why it did not fit, instead of asserting that the kernel is bad.
    #[test]
    fn no_room_for_the_initramfs_reports_the_window_it_could_not_fit() {
        // Kernel ends past where the DTB window starts: nothing can fit.
        let err = initrd_load_offset(4096, 1 << 20, 8192).expect_err("cannot fit");
        assert_eq!(
            err,
            HvfError::BadBoot(BootFault::InitrdNoRoom {
                kernel_end: 4096,
                initrd_len: 1 << 20,
                dtb_offset: 8192,
            })
        );
    }
}
