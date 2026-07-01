//! The hypervisor backend seam — the portable contract between the device model
//! / run loop ([`crate::vmm`]) and the concrete VMM it runs on (HVF on macOS,
//! KVM on Linux, WHP on Windows later).
//!
//! It is drawn **high**: guest memory, vCPU register state, IRQ raise, and the
//! run/exit primitive live here; everything *below* (how a backend services
//! device doorbells or injects interrupts natively) is the backend's own
//! business. So the run loop and device dispatch are written **once** against
//! this contract and each platform supplies the native implementation.
//!
//! Dispatch is **static**: the active backend is bound as a concrete type at
//! compile time ([`ActiveVm`]), so trait calls monomorphize to direct calls —
//! no `dyn` on the vCPU hot path. The register model is aarch64-architectural
//! today (HVF and aarch64 KVM expose the same registers, each mapping them to
//! its native id); an x86_64 backend extends [`VcpuExit`] with its decoded
//! `Io`/`Mmio` exits, which the run loop already understands.

/// aarch64 core registers the run loop touches. Backends map each to a native id
/// (HVF `hv_reg_t`; KVM `KVM_REG_ARM_CORE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreReg {
    /// `X0..=X30` (values > 30 are rejected by the backend).
    X(u8),
    /// Program counter.
    Pc,
    /// Processor state (PSTATE / CPSR).
    Cpsr,
}

/// aarch64 system registers the run loop touches (extend as backends migrate
/// more of the boot/snapshot surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysReg {
    /// Multiprocessor Affinity Register — per-vCPU identity; must match the
    /// device tree's `cpu` reg and the GIC redistributor frame.
    MpidrEl1,
}

/// Guest-memory protection flags for [`HypervisorVm::map_ram`]. Portable bit
/// layout; each backend translates to its native mapping flags.
pub mod prot {
    pub const READ: u64 = 1;
    pub const WRITE: u64 = 1 << 1;
    pub const EXEC: u64 = 1 << 2;
    pub const RWX: u64 = READ | WRITE | EXEC;
}

/// Why a vCPU stopped. Small and `Copy` — no allocation on the run/exit hot
/// path. Unifies the two ways a guest MMIO access surfaces:
/// - **`Exception`** — the raw arm64 trap (HVF): the run loop decodes the ESR
///   to locate the access (this is what `hvf` produces today).
/// - **`Mmio` / `Io`** — already decoded by the hypervisor (KVM
///   `KVM_EXIT_MMIO` / `KVM_EXIT_IO`): the run loop dispatches them directly.
///
/// Both forms route to the same device-model handler, so one run loop serves
/// every backend and architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuExit {
    /// The run was cancelled from another thread (see [`VcpuHandle::force_exit`]).
    Canceled,
    /// A guest exception trapped to the host (arm64/HVF). `syndrome` is the ESR;
    /// `phys_addr` is the faulting IPA for a data abort.
    Exception { syndrome: u64, phys_addr: u64 },
    /// A decoded MMIO access (KVM). `data` holds the written value for a write; a
    /// read is completed by the run loop before the next [`HypervisorVcpu::step`].
    Mmio {
        phys_addr: u64,
        write: bool,
        len: u8,
        data: u64,
    },
    /// A decoded x86 port-I/O access (KVM `KVM_EXIT_IO`).
    Io {
        port: u16,
        write: bool,
        size: u8,
        data: u32,
    },
    /// The virtual timer fired (re-enter the vCPU).
    VTimer,
    /// The guest halted or requested shutdown.
    Halt,
    /// A reason this run loop does not model; carries the raw backend code.
    Unknown(u32),
}

/// An opaque, thread-safe token identifying a vCPU, usable from a *different*
/// thread to force it out of [`HypervisorVcpu::step`] (e.g. a run watchdog, or a
/// snapshot rendezvous). vCPUs are thread-bound, but the orchestration holds
/// these tokens to interrupt them without owning the `Vcpu`.
pub trait VcpuHandle: Copy + Send + Sync + 'static {
    /// Force the given vCPUs out of `step()`, callable from any thread. Batched:
    /// HVF does it in one call (`hv_vcpus_exit`); KVM signals each thread.
    fn force_exit(handles: &[Self]);
}

/// A single vCPU. The run loop drives it only through this trait, so register
/// plumbing + the run/exit loop are written once and each backend supplies the
/// native implementation.
pub trait HypervisorVcpu {
    /// Backend-native error.
    type Error;
    /// Cross-thread force-exit token.
    type Handle: VcpuHandle;

    /// A token usable from another thread to force-exit this vCPU.
    fn exit_token(&self) -> Self::Handle;

    fn get_core(&self, reg: CoreReg) -> Result<u64, Self::Error>;
    fn set_core(&self, reg: CoreReg, value: u64) -> Result<(), Self::Error>;
    fn get_sys(&self, reg: SysReg) -> Result<u64, Self::Error>;
    fn set_sys(&self, reg: SysReg, value: u64) -> Result<(), Self::Error>;

    /// Run the vCPU until it exits. Hot path: returns a `Copy` exit, no
    /// allocation, inlinable under static dispatch. A guest *read* surfaces as
    /// `Mmio`/`Io` with `write == false` and `data == 0`; the run loop computes
    /// the value from the device model and hands it back via [`complete_read`]
    /// before the next `step`.
    ///
    /// [`complete_read`]: HypervisorVcpu::complete_read
    fn step(&self) -> Result<VcpuExit, Self::Error>;

    /// Deliver the result `value` of the read that the last [`step`] surfaced
    /// (`Mmio`/`Io`, `write == false`) to the guest, completing the load: KVM
    /// fills the `kvm_run` data buffer (the kernel finishes the load on
    /// re-entry); HVF writes the destination register and advances PC. A no-op
    /// if the last exit was not a pending read.
    ///
    /// [`step`]: HypervisorVcpu::step
    fn complete_read(&self, value: u64) -> Result<(), Self::Error>;
}

/// A VM: owns guest physical memory, its interrupt controller, and creates
/// vCPUs. One backend type implements this per platform, selected as a concrete
/// type at compile time ([`ActiveVm`]) — never behind `dyn`.
pub trait HypervisorVm: Sized {
    type Error;
    type Vcpu: HypervisorVcpu<Error = Self::Error>;

    /// Create the VM and its in-kernel interrupt controller.
    fn create() -> Result<Self, Self::Error>;

    /// Map `len` bytes of host memory at `host_ptr` as guest physical memory at
    /// `gpa` with the given [`prot`] flags.
    ///
    /// # Safety
    /// `host_ptr` must stay valid + accessible per `prot` for the VM's lifetime.
    unsafe fn map_ram(
        &self,
        host_ptr: *mut u8,
        gpa: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), Self::Error>;

    /// Create a vCPU bound to the calling thread.
    fn create_vcpu(&self) -> Result<Self::Vcpu, Self::Error>;

    /// Raise (`level = true`) or lower the interrupt line `intid` (SPI/GSI) into
    /// the guest's interrupt controller — the backend-agnostic IRQ-raise the
    /// device model calls when a virtio device has work. HVF: `hv_gic_set_spi`;
    /// KVM: `KVM_IRQ_LINE`. Edge-triggered virtio IRQs raise (and the controller
    /// auto-deasserts on EOI).
    fn set_irq(&self, intid: u32, level: bool) -> Result<(), Self::Error>;
}

// ----------------------------------------------------------------------------
// Static, cfg-selected active backend. macOS/Apple-silicon → HVF; the Linux/KVM
// and Windows/WHP branches bind their concrete types here as they land. The
// orchestration names `Active*` and never a concrete backend type.
// ----------------------------------------------------------------------------

/// The hypervisor backend selected for this build. Bound as a concrete type so
/// all dispatch is static.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub type ActiveVm = crate::hvf::HvfVm;

/// Linux/x86_64 → KVM. (aarch64 KVM, which reuses the whole arm64 device model,
/// is a later slice.)
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub type ActiveVm = crate::kvm::KvmVm;
