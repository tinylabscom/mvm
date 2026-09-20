//! HVF state codecs for the in-house snapshot frame.
//!
//! The codec is deliberately limited to architecturally visible state that
//! this backend can currently read and write: the 31 AArch64 general-purpose
//! registers, PC, and CPSR. Device state and RAM are carried by separate
//! sections in [`mvm_core::snapshot_frame`]; capability admission remains off
//! until the live pause/serialize/restore loop owns all of those sections.

use super::HvfError;
use super::guest_ram::{GuestRam, HVF_PAGE_SIZE};
use super::sys::{
    HV_SUCCESS, hv_gic_icc_reg_t, hv_gic_set_state, hv_gic_state_create, hv_gic_state_get_data,
    hv_gic_state_get_size, hv_gic_state_t, os_release,
};
use crate::vmm::device_state::{DeviceStateError, SnapshotDeviceState, restore_device_states};
use crate::vmm::hv::SysReg;
use mvm_core::arch::GuestArch;
use mvm_core::snapshot_frame::{
    FrameError, SectionKind, SnapshotSection, parse_header, parse_sections,
};

/// System registers serialized in architectural resume order.
pub const SNAPSHOT_SYS_REGS: [SysReg; 15] = [
    SysReg::MpidrEl1,
    SysReg::SctlrEl1,
    SysReg::Ttbr0El1,
    SysReg::Ttbr1El1,
    SysReg::TcrEl1,
    SysReg::MairEl1,
    SysReg::VbarEl1,
    SysReg::EsrEl1,
    SysReg::FarEl1,
    SysReg::ElrEl1,
    SysReg::SpEl1,
    SysReg::SpsrEl1,
    SysReg::CntkctlEl1,
    SysReg::CntvCtlEl0,
    SysReg::CntvCvalEl0,
];
/// Additional writable HVF system registers required to resume either an EL0
/// task or the EL1 kernel context that was interrupted to capture it.
pub const SNAPSHOT_EXTRA_SYS_REGS: [super::sys::hv_sys_reg_t; 17] = [
    super::sys::HV_SYS_REG_ACTLR_EL1,
    super::sys::HV_SYS_REG_CPACR_EL1,
    super::sys::HV_SYS_REG_APIAKEYLO_EL1,
    super::sys::HV_SYS_REG_APIAKEYHI_EL1,
    super::sys::HV_SYS_REG_APIBKEYLO_EL1,
    super::sys::HV_SYS_REG_APIBKEYHI_EL1,
    super::sys::HV_SYS_REG_APDAKEYLO_EL1,
    super::sys::HV_SYS_REG_APDAKEYHI_EL1,
    super::sys::HV_SYS_REG_APDBKEYLO_EL1,
    super::sys::HV_SYS_REG_APDBKEYHI_EL1,
    super::sys::HV_SYS_REG_APGAKEYLO_EL1,
    super::sys::HV_SYS_REG_APGAKEYHI_EL1,
    super::sys::HV_SYS_REG_SP_EL0,
    super::sys::HV_SYS_REG_CONTEXTIDR_EL1,
    super::sys::HV_SYS_REG_TPIDR_EL1,
    super::sys::HV_SYS_REG_TPIDR_EL0,
    super::sys::HV_SYS_REG_TPIDRRO_EL0,
];
/// GIC CPU-interface registers serialized for each vCPU.
pub const SNAPSHOT_GIC_ICC_REGS: [hv_gic_icc_reg_t; 10] = [
    0xc230, 0xc643, 0xc644, 0xc648, 0xc65b, 0xc663, 0xc664, 0xc665, 0xc666, 0xc667,
];
/// Whether Hypervisor.framework permits restoring this ICC register directly.
/// `ICC_RPR_EL1` is read-only and is recomputed from the active-priority state.
pub const fn gic_icc_is_restorable(reg: hv_gic_icc_reg_t) -> bool {
    reg != 0xc65b
}
/// Number of serialized 64-bit AArch64 register words.
pub const VCPU_STATE_WORDS: usize =
    35 + SNAPSHOT_SYS_REGS.len() + SNAPSHOT_EXTRA_SYS_REGS.len() + SNAPSHOT_GIC_ICC_REGS.len();
/// Number of 128-bit SIMD/FP registers in AArch64 architectural state.
pub const VCPU_SIMD_REGS: usize = 32;
/// Fixed encoded length of [`HvfVcpuState`].
pub const VCPU_STATE_LEN: usize = VCPU_STATE_WORDS * 8 + VCPU_SIMD_REGS * 16;
/// Stable frame identity for the first-party HVF device model.
pub const HVF_SNAPSHOT_BACKEND_KIND: u8 = 1;
/// Backend-private section kind carrying Hypervisor.framework's opaque,
/// versioned GIC distributor and redistributor state.
pub const HVF_GIC_STATE_SECTION_KIND: u16 = 5;
/// Backend-private section kind describing where guest RAM sits in the RAM
/// image file saved beside the frame.
pub const HVF_RAM_LAYOUT_SECTION_KIND: u16 = 6;
/// Encoded length of [`RamLayout`]: file offset (8) + length (8) + page size (4).
pub const RAM_LAYOUT_LEN: usize = 20;

/// Where guest RAM sits in its image file.
///
/// A restore maps this range of the file over the guest's RAM reservation, so
/// both ends must fall on a hypervisor page boundary: the mapping replaces whole
/// pages, and a range that started or ended mid-page could not be mapped
/// without either dropping guest bytes or exposing bytes that are not guest RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamLayout {
    /// Byte offset of guest RAM within the image file.
    pub file_offset: u64,
    /// Length of guest RAM in bytes.
    pub len: u64,
    /// The page size the producer aligned the range to.
    pub page_size: u32,
}

/// Why a [`RamLayout`] cannot be mapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RamLayoutError {
    /// The section is not exactly [`RAM_LAYOUT_LEN`] bytes.
    Encoding { len: usize },
    /// The producer aligned to a page size this hypervisor does not use.
    PageSize { expected: u32, actual: u32 },
    /// The RAM does not start on a page boundary.
    MisalignedOffset { offset: u64 },
    /// The RAM does not end on a page boundary.
    MisalignedLength { len: u64 },
    /// Offset plus length does not fit in a file offset.
    Overflow,
}

impl std::fmt::Display for RamLayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding { len } => write!(f, "RAM layout section is {len} bytes"),
            Self::PageSize { expected, actual } => {
                write!(f, "RAM aligned to page size {actual}, expected {expected}")
            }
            Self::MisalignedOffset { offset } => {
                write!(f, "RAM file offset {offset} is not page-aligned")
            }
            Self::MisalignedLength { len } => write!(f, "RAM length {len} is not page-aligned"),
            Self::Overflow => write!(f, "RAM file range overflows"),
        }
    }
}

impl RamLayout {
    /// Guest RAM stored as a whole file of `len` bytes, starting at offset 0.
    #[must_use]
    pub fn whole_file(len: usize) -> Self {
        Self {
            file_offset: 0,
            len: len as u64,
            page_size: HVF_PAGE_SIZE as u32,
        }
    }

    /// Little-endian encoding: offset, length, page size.
    #[must_use]
    pub fn encode(&self) -> [u8; RAM_LAYOUT_LEN] {
        let mut bytes = [0_u8; RAM_LAYOUT_LEN];
        bytes[..8].copy_from_slice(&self.file_offset.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.len.to_le_bytes());
        bytes[16..].copy_from_slice(&self.page_size.to_le_bytes());
        bytes
    }

    /// Decode the fixed-width encoding produced by [`RamLayout::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, RamLayoutError> {
        let bytes: &[u8; RAM_LAYOUT_LEN] = bytes
            .try_into()
            .map_err(|_| RamLayoutError::Encoding { len: bytes.len() })?;
        let mut offset = [0_u8; 8];
        offset.copy_from_slice(&bytes[..8]);
        let mut len = [0_u8; 8];
        len.copy_from_slice(&bytes[8..16]);
        let mut page = [0_u8; 4];
        page.copy_from_slice(&bytes[16..]);
        Ok(Self {
            file_offset: u64::from_le_bytes(offset),
            len: u64::from_le_bytes(len),
            page_size: u32::from_le_bytes(page),
        })
    }

    /// Check the range can be mapped over a reservation of `expected_ram_len`
    /// bytes on this hypervisor.
    pub fn validate(&self, expected_ram_len: usize) -> Result<(), HvfSnapshotError> {
        let page = HVF_PAGE_SIZE as u64;
        if u64::from(self.page_size) != page {
            return Err(RamLayoutError::PageSize {
                expected: HVF_PAGE_SIZE as u32,
                actual: self.page_size,
            }
            .into());
        }
        if !self.file_offset.is_multiple_of(page) {
            return Err(RamLayoutError::MisalignedOffset {
                offset: self.file_offset,
            }
            .into());
        }
        if !self.len.is_multiple_of(page) {
            return Err(RamLayoutError::MisalignedLength { len: self.len }.into());
        }
        self.file_end()?;
        if self.len != expected_ram_len as u64 {
            return Err(HvfSnapshotError::RamLength {
                expected: expected_ram_len,
                actual: usize::try_from(self.len).unwrap_or(usize::MAX),
            });
        }
        Ok(())
    }

    /// The first file offset past guest RAM.
    pub fn file_end(&self) -> Result<u64, RamLayoutError> {
        self.file_offset
            .checked_add(self.len)
            .filter(|end| i64::try_from(*end).is_ok())
            .ok_or(RamLayoutError::Overflow)
    }
}

/// Errors raised while assembling or validating one complete HVF snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HvfSnapshotError {
    /// The outer frame was malformed or unsupported.
    Frame(FrameError),
    /// A device-specific section was malformed or did not match the target.
    Devices(DeviceStateError),
    /// HVF refused to read or write the vCPU register state.
    Vcpu(HvfError),
    /// The frame was produced for a different backend identity.
    BackendMismatch { expected: u8, actual: u8 },
    /// The frame was produced for a non-AArch64 guest.
    WrongArchitecture(GuestArch),
    /// A required section was absent.
    MissingSection(SectionKind),
    /// A required section appeared more than once.
    DuplicateSection(SectionKind),
    /// The RAM section did not match the target mapping exactly.
    RamLength { expected: usize, actual: usize },
    /// The RAM layout cannot be mapped.
    RamLayout(RamLayoutError),
    /// The frame carries guest RAM inline, a layout this build does not restore.
    InlineRam,
}

impl std::fmt::Display for HvfSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "HVF snapshot frame: {error}"),
            Self::Devices(error) => write!(f, "HVF snapshot devices: {error}"),
            Self::Vcpu(error) => write!(f, "HVF snapshot vCPU: {error:?}"),
            Self::BackendMismatch { expected, actual } => {
                write!(
                    f,
                    "HVF snapshot backend mismatch: expected {expected}, got {actual}"
                )
            }
            Self::WrongArchitecture(arch) => {
                write!(f, "HVF snapshot architecture is {arch}, expected aarch64")
            }
            Self::MissingSection(kind) => write!(f, "HVF snapshot missing {kind:?} section"),
            Self::DuplicateSection(kind) => {
                write!(f, "HVF snapshot contains duplicate {kind:?} sections")
            }
            Self::RamLength { expected, actual } => {
                write!(
                    f,
                    "HVF snapshot RAM length {actual} does not match {expected}"
                )
            }
            Self::RamLayout(error) => write!(f, "HVF snapshot RAM layout: {error}"),
            Self::InlineRam => write!(
                f,
                "HVF snapshot carries guest RAM inside its frame, a format this build no \
                 longer restores; capture the checkpoint again"
            ),
        }
    }
}

impl std::error::Error for HvfSnapshotError {}

impl From<FrameError> for HvfSnapshotError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<RamLayoutError> for HvfSnapshotError {
    fn from(error: RamLayoutError) -> Self {
        Self::RamLayout(error)
    }
}

impl From<DeviceStateError> for HvfSnapshotError {
    fn from(error: DeviceStateError) -> Self {
        Self::Devices(error)
    }
}

/// The validated sections of one AArch64 HVF snapshot frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHvfSnapshot<'a> {
    /// Where guest RAM sits in the image file saved beside the frame.
    pub ram: RamLayout,
    /// Versioned device-state container.
    pub devices: &'a [u8],
    /// Opaque, versioned GIC distributor and redistributor state.
    pub gic: &'a [u8],
    /// Decoded AArch64 core-register state, one entry per vCPU in CPU order.
    ///
    /// Always at least one — the boot CPU. A machine with more carries them all,
    /// because a restored child has to resume every CPU its parent was running.
    /// Resuming only CPU 0 would leave the guest's scheduler dispatching onto
    /// CPUs that exist in its own tables and are executing nothing.
    pub vcpus: Vec<HvfVcpuState>,
    /// Artifact identity metadata carried by the producer.
    pub artifact_digests: &'a [u8],
}

/// A stable, little-endian representation of the AArch64 core state HVF
/// exposes through its register API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvfVcpuState {
    /// General-purpose registers X0 through X30.
    pub x: [u64; 31],
    /// Program counter.
    pub pc: u64,
    /// Current program status register.
    pub cpsr: u64,
    /// System-register state in [`SNAPSHOT_SYS_REGS`] order.
    pub sys: [u64; SNAPSHOT_SYS_REGS.len()],
    /// Additional raw HVF system registers in [`SNAPSHOT_EXTRA_SYS_REGS`] order.
    pub extra_sys: [u64; SNAPSHOT_EXTRA_SYS_REGS.len()],
    /// GIC CPU-interface state in [`SNAPSHOT_GIC_ICC_REGS`] order.
    pub gic_icc: [u64; SNAPSHOT_GIC_ICC_REGS.len()],
    /// Floating-point control and status registers.
    pub fpcr: u64,
    pub fpsr: u64,
    /// Q0 through Q31, preserving the complete non-streaming SIMD/FP state.
    pub simd: [[u8; 16]; VCPU_SIMD_REGS],
}

impl HvfVcpuState {
    /// Encode the state as 31 general-purpose registers followed by PC and
    /// CPSR, all as little-endian u64 words.
    #[must_use]
    pub fn encode(&self) -> [u8; VCPU_STATE_LEN] {
        let mut bytes = [0u8; VCPU_STATE_LEN];
        for (index, value) in self.x.iter().copied().enumerate() {
            let start = index * 8;
            bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[31 * 8..32 * 8].copy_from_slice(&self.pc.to_le_bytes());
        bytes[32 * 8..33 * 8].copy_from_slice(&self.cpsr.to_le_bytes());
        for (index, value) in self.sys.iter().copied().enumerate() {
            let start = (33 + index) * 8;
            bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (index, value) in self.gic_icc.iter().copied().enumerate() {
            let start = (33 + SNAPSHOT_SYS_REGS.len() + SNAPSHOT_EXTRA_SYS_REGS.len() + index) * 8;
            bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (index, value) in self.extra_sys.iter().copied().enumerate() {
            let start = (33 + SNAPSHOT_SYS_REGS.len() + index) * 8;
            bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        let fpcr_index = 33
            + SNAPSHOT_SYS_REGS.len()
            + SNAPSHOT_EXTRA_SYS_REGS.len()
            + SNAPSHOT_GIC_ICC_REGS.len();
        bytes[fpcr_index * 8..(fpcr_index + 1) * 8].copy_from_slice(&self.fpcr.to_le_bytes());
        bytes[(fpcr_index + 1) * 8..(fpcr_index + 2) * 8].copy_from_slice(&self.fpsr.to_le_bytes());
        let simd_start = VCPU_STATE_WORDS * 8;
        for (index, value) in self.simd.iter().enumerate() {
            let start = simd_start + index * 16;
            bytes[start..start + 16].copy_from_slice(value);
        }
        bytes
    }

    /// Decode the fixed-width little-endian representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, HvfError> {
        if bytes.len() != VCPU_STATE_LEN {
            return Err(HvfError::SnapshotState("invalid vCPU state length"));
        }
        let mut x = [0u64; 31];
        for (index, slot) in x.iter_mut().enumerate() {
            *slot = read_word(bytes, index)?;
        }
        let mut sys = [0u64; SNAPSHOT_SYS_REGS.len()];
        for (index, slot) in sys.iter_mut().enumerate() {
            *slot = read_word(bytes, 33 + index)?;
        }
        let mut gic_icc = [0u64; SNAPSHOT_GIC_ICC_REGS.len()];
        for (index, slot) in gic_icc.iter_mut().enumerate() {
            *slot = read_word(
                bytes,
                33 + SNAPSHOT_SYS_REGS.len() + SNAPSHOT_EXTRA_SYS_REGS.len() + index,
            )?;
        }
        let mut extra_sys = [0u64; SNAPSHOT_EXTRA_SYS_REGS.len()];
        for (index, slot) in extra_sys.iter_mut().enumerate() {
            *slot = read_word(bytes, 33 + SNAPSHOT_SYS_REGS.len() + index)?;
        }
        let fpcr_index = 33
            + SNAPSHOT_SYS_REGS.len()
            + SNAPSHOT_EXTRA_SYS_REGS.len()
            + SNAPSHOT_GIC_ICC_REGS.len();
        let mut simd = [[0u8; 16]; VCPU_SIMD_REGS];
        let simd_start = VCPU_STATE_WORDS * 8;
        for (index, slot) in simd.iter_mut().enumerate() {
            let start = simd_start + index * 16;
            slot.copy_from_slice(&bytes[start..start + 16]);
        }
        Ok(Self {
            x,
            pc: read_word(bytes, 31)?,
            cpsr: read_word(bytes, 32)?,
            sys,
            extra_sys,
            gic_icc,
            fpcr: read_word(bytes, fpcr_index)?,
            fpsr: read_word(bytes, fpcr_index + 1)?,
            simd,
        })
    }
}

struct GicStateObject(hv_gic_state_t);

impl Drop for GicStateObject {
    fn drop(&mut self) {
        // SAFETY: `hv_gic_state_create` returned this retained OS object and it
        // has not been released elsewhere.
        unsafe { os_release(self.0.cast()) };
    }
}

/// Capture Hypervisor.framework's complete non-CPU GIC state while every vCPU
/// is stopped at the snapshot boundary.
pub fn capture_gic_device_state() -> Result<Vec<u8>, HvfError> {
    // SAFETY: the caller holds every vCPU outside `hv_vcpu_run`; the returned
    // retained object is owned by `GicStateObject` until this function returns.
    let state = unsafe { hv_gic_state_create() };
    if state.is_null() {
        return Err(HvfError::SnapshotState("GIC state object capture failed"));
    }
    let state = GicStateObject(state);
    let mut size = 0usize;
    // SAFETY: `state` is live and `size` is a valid out-parameter.
    let rc = unsafe { hv_gic_state_get_size(state.0, &mut size) };
    if rc != HV_SUCCESS {
        return Err(HvfError::GicDeviceCapture(rc));
    }
    if size == 0 {
        return Err(HvfError::SnapshotState("GIC state payload is empty"));
    }
    let mut bytes = vec![0u8; size];
    // SAFETY: `bytes` has at least the exact size the state object reported.
    let rc = unsafe { hv_gic_state_get_data(state.0, bytes.as_mut_ptr().cast()) };
    if rc != HV_SUCCESS {
        return Err(HvfError::GicDeviceCapture(rc));
    }
    Ok(bytes)
}

/// Restore Hypervisor.framework's opaque GIC device state after every vCPU has
/// been created and before any vCPU is allowed to run.
pub fn restore_gic_device_state(bytes: &[u8]) -> Result<(), HvfError> {
    if bytes.is_empty() {
        return Err(HvfError::SnapshotState("GIC state payload is empty"));
    }
    // SAFETY: the GIC and every vCPU exist, none has run, and `bytes` remains
    // valid for the duration of the call.
    let rc = unsafe { hv_gic_set_state(bytes.as_ptr().cast(), bytes.len()) };
    if rc == HV_SUCCESS {
        Ok(())
    } else {
        Err(HvfError::GicDeviceRestore(rc))
    }
}

/// Assemble the sections owned by an HVF snapshot producer. The device and
/// artifact payloads are supplied by their respective serializers; this
/// function only makes their placement and frame metadata unambiguous.
///
/// Guest RAM is not a section of the frame. It lives in its own file, described
/// here by `ram`, so a restore can map it instead of reading it: a frame that
/// carried the RAM inline would have to be read whole — a second copy of the
/// guest's memory — just to reach the few kilobytes of CPU and device state
/// beside it.
pub fn encode_hvf_snapshot_frame(
    backend_kind: u8,
    flags: u32,
    ram: RamLayout,
    devices: &[u8],
    gic: &[u8],
    vcpus: &[HvfVcpuState],
    artifact_digests: &[u8],
) -> Result<Vec<u8>, FrameError> {
    // Every CPU's state, concatenated in CPU order. Fixed-width records, so the
    // count is the section length over the record length and no separate field
    // can disagree with the payload.
    let vcpu_bytes: Vec<u8> = vcpus.iter().flat_map(|state| state.encode()).collect();
    let layout = ram.encode();
    mvm_core::snapshot_frame::encode_frame(
        GuestArch::Aarch64,
        backend_kind,
        flags,
        &[
            SnapshotSection {
                kind: SectionKind::Unknown(HVF_RAM_LAYOUT_SECTION_KIND),
                data: &layout,
            },
            SnapshotSection {
                kind: SectionKind::Devices,
                data: devices,
            },
            SnapshotSection {
                kind: SectionKind::Unknown(HVF_GIC_STATE_SECTION_KIND),
                data: gic,
            },
            SnapshotSection {
                kind: SectionKind::Vcpu,
                data: &vcpu_bytes,
            },
            SnapshotSection {
                kind: SectionKind::ArtifactDigests,
                data: artifact_digests,
            },
        ],
    )
}

/// Write the paused guest's RAM to `path` straight from the live mapping and
/// return the layout a frame records for it.
///
/// Streams in bounded chunks rather than collecting the image first, so a
/// capture holds no second copy of guest memory in the supervisor. The bytes
/// come from the mapping, never from a file a restore mapped it from: pages the
/// guest wrote since its own restore are private copies, and those are the
/// bytes the new snapshot has to carry.
pub fn write_ram_image(ram: &GuestRam, path: &std::path::Path) -> std::io::Result<RamLayout> {
    let mut file = std::fs::File::create(path)?;
    ram.write_to(&mut file)?;
    file.sync_all()?;
    Ok(RamLayout::whole_file(ram.len()))
}

/// Parse and validate a complete HVF snapshot before any target is mutated.
pub fn parse_hvf_snapshot_frame<'a>(
    frame: &'a [u8],
    expected_backend_kind: u8,
    expected_ram_len: usize,
) -> Result<ParsedHvfSnapshot<'a>, HvfSnapshotError> {
    let header = parse_header(frame)?;
    if header.arch != GuestArch::Aarch64 {
        return Err(HvfSnapshotError::WrongArchitecture(header.arch));
    }
    if header.backend_kind != expected_backend_kind {
        return Err(HvfSnapshotError::BackendMismatch {
            expected: expected_backend_kind,
            actual: header.backend_kind,
        });
    }

    let mut ram = None;
    let mut devices = None;
    let mut gic = None;
    let mut vcpu = None;
    let mut artifact_digests = None;
    for entry in parse_sections(frame)? {
        let slot = match entry.kind {
            // A frame from before RAM moved out of it. Refused by name rather
            // than skipped as unknown: skipping would report a missing layout,
            // which reads as corruption instead of as an old capture.
            SectionKind::Ram => return Err(HvfSnapshotError::InlineRam),
            SectionKind::Unknown(HVF_RAM_LAYOUT_SECTION_KIND) => &mut ram,
            SectionKind::Devices => &mut devices,
            SectionKind::Unknown(HVF_GIC_STATE_SECTION_KIND) => &mut gic,
            SectionKind::Vcpu => &mut vcpu,
            SectionKind::ArtifactDigests => &mut artifact_digests,
            SectionKind::Unknown(_) => continue,
        };
        if slot.is_some() {
            return Err(HvfSnapshotError::DuplicateSection(entry.kind));
        }
        *slot = Some(entry.data(frame));
    }

    let ram = ram.ok_or(HvfSnapshotError::MissingSection(SectionKind::Unknown(
        HVF_RAM_LAYOUT_SECTION_KIND,
    )))?;
    let ram = RamLayout::decode(ram)?;
    ram.validate(expected_ram_len)?;
    let devices = devices.ok_or(HvfSnapshotError::MissingSection(SectionKind::Devices))?;
    let gic = gic.ok_or(HvfSnapshotError::MissingSection(SectionKind::Unknown(
        HVF_GIC_STATE_SECTION_KIND,
    )))?;
    let vcpu_bytes = vcpu.ok_or(HvfSnapshotError::MissingSection(SectionKind::Vcpu))?;
    let artifact_digests = artifact_digests.ok_or(HvfSnapshotError::MissingSection(
        SectionKind::ArtifactDigests,
    ))?;

    Ok(ParsedHvfSnapshot {
        ram,
        devices,
        gic,
        vcpus: decode_vcpu_states(vcpu_bytes)?,
        artifact_digests,
    })
}

/// Return the CPU count from a fully validated HVF snapshot frame.
///
/// Callers can use this before constructing restore targets so a machine-shape
/// mismatch is refused before any device or vCPU state is mutated.
pub fn hvf_snapshot_vcpu_count(
    frame: &[u8],
    expected_ram_len: usize,
) -> Result<usize, HvfSnapshotError> {
    let parsed = parse_hvf_snapshot_frame(frame, HVF_SNAPSHOT_BACKEND_KIND, expected_ram_len)?;
    Ok(parsed.vcpus.len())
}

/// Decode the vCPU section as one fixed-width record per CPU.
///
/// A section that is not a whole number of records, or that carries no CPU at
/// all, is refused rather than truncated: the count is derived from the length,
/// so a partial trailing record would otherwise silently drop a CPU and produce
/// a child running fewer CPUs than the guest inside it believes it has.
fn decode_vcpu_states(bytes: &[u8]) -> Result<Vec<HvfVcpuState>, HvfSnapshotError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(VCPU_STATE_LEN) {
        return Err(HvfSnapshotError::Vcpu(HvfError::SnapshotState(
            "vCPU section is not a whole number of vCPU records",
        )));
    }
    bytes
        .chunks(VCPU_STATE_LEN)
        .map(|record| HvfVcpuState::decode(record).map_err(HvfSnapshotError::Vcpu))
        .collect()
}

/// The verified saved state a restored supervisor boots from, as descriptors.
///
/// Both files are the private, unlinked copies the launching process verified
/// against the checkpoint's recorded digests. Nothing here holds a path: a
/// restore that could reopen its inputs by name could be handed different
/// bytes than the ones that were checked.
#[derive(Debug)]
pub struct RestoreImage {
    /// Guest RAM, mapped copy-on-write at the layout the frame records.
    pub ram: std::fs::File,
    /// The frame carrying vCPU, GIC and device state.
    pub frame: std::fs::File,
}

/// Validate the frame in `image` and map its RAM over `guest_ram`.
///
/// Returns the frame bytes for the device and vCPU restore that follows once
/// the machine exists. The mapping has to be in place before the reservation is
/// registered with the hypervisor, which registers whatever backs the range at
/// that moment.
pub fn map_restore_image(
    image: &RestoreImage,
    guest_ram: &mut GuestRam,
) -> Result<Vec<u8>, HvfError> {
    use std::io::Read as _;
    let mut frame = Vec::new();
    (&image.frame)
        .read_to_end(&mut frame)
        .map_err(|_| HvfError::SnapshotState("restore frame read failed"))?;
    let parsed = parse_hvf_snapshot_frame(&frame, HVF_SNAPSHOT_BACKEND_KIND, guest_ram.len())
        .map_err(|error| {
            eprintln!("HVF restore frame refused: {error}");
            HvfError::SnapshotState("restore frame validation failed")
        })?;
    guest_ram.map_snapshot_ram(&image.ram, parsed.ram)?;
    Ok(frame)
}

/// Restore only vCPU and deterministic device state from a frame whose RAM is
/// already privately mapped by [`map_restore_image`].
pub fn restore_hvf_snapshot_control(
    frame: &[u8],
    expected_ram_len: usize,
    devices: &mut [&mut dyn SnapshotDeviceState],
) -> Result<RestoredHvfControl, HvfSnapshotError> {
    let parsed = parse_hvf_snapshot_frame(frame, HVF_SNAPSHOT_BACKEND_KIND, expected_ram_len)?;
    restore_device_states(devices, parsed.devices)?;
    Ok(RestoredHvfControl {
        vcpus: parsed.vcpus,
        gic: parsed.gic.to_vec(),
    })
}

/// Validated control state held until every restored vCPU exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredHvfControl {
    /// Core and GIC CPU-interface state, in CPU order.
    pub vcpus: Vec<HvfVcpuState>,
    /// Opaque GIC distributor and redistributor state.
    pub gic: Vec<u8>,
}

fn read_word(bytes: &[u8], index: usize) -> Result<u64, HvfError> {
    let start = index
        .checked_mul(8)
        .ok_or(HvfError::SnapshotState("vCPU state offset overflow"))?;
    let end = start
        .checked_add(8)
        .ok_or(HvfError::SnapshotState("vCPU state offset overflow"))?;
    let word = bytes
        .get(start..end)
        .ok_or(HvfError::SnapshotState("vCPU state word is truncated"))?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(word);
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RAM_LEN: usize = HVF_PAGE_SIZE * 2;

    fn test_layout() -> RamLayout {
        RamLayout::whole_file(TEST_RAM_LEN)
    }

    #[test]
    fn state_codec_roundtrips_all_registers() {
        let state = HvfVcpuState {
            x: core::array::from_fn(|index| 0x1000 + index as u64),
            pc: 0x4000,
            cpsr: 0x3c5,
            sys: core::array::from_fn(|index| index as u64),
            extra_sys: core::array::from_fn(|index| 0x80 + index as u64),
            gic_icc: core::array::from_fn(|index| 0x100 + index as u64),
            fpcr: 0x1234,
            fpsr: 0x5678,
            simd: core::array::from_fn(|index| [index as u8; 16]),
        };
        let encoded = state.encode();
        assert_eq!(encoded.len(), VCPU_STATE_LEN);
        assert_eq!(HvfVcpuState::decode(&encoded).unwrap(), state);
    }

    #[test]
    fn only_the_derived_running_priority_register_is_not_restored() {
        let refused: Vec<_> = SNAPSHOT_GIC_ICC_REGS
            .iter()
            .copied()
            .filter(|reg| !gic_icc_is_restorable(*reg))
            .collect();
        assert_eq!(refused, vec![0xc65b]);
    }

    #[test]
    fn state_codec_rejects_truncated_and_extended_input() {
        assert!(matches!(
            HvfVcpuState::decode(&[0u8; VCPU_STATE_LEN - 1]),
            Err(HvfError::SnapshotState("invalid vCPU state length"))
        ));
        assert!(matches!(
            HvfVcpuState::decode(&[0u8; VCPU_STATE_LEN + 1]),
            Err(HvfError::SnapshotState("invalid vCPU state length"))
        ));
    }

    #[test]
    fn frame_codec_places_register_state_with_ram_and_metadata() {
        let state = HvfVcpuState {
            x: [7; 31],
            pc: 0x8000,
            cpsr: 0x3c5,
            sys: [0; SNAPSHOT_SYS_REGS.len()],
            extra_sys: [0; SNAPSHOT_EXTRA_SYS_REGS.len()],
            gic_icc: [0; SNAPSHOT_GIC_ICC_REGS.len()],
            fpcr: 0,
            fpsr: 0,
            simd: [[0; 16]; VCPU_SIMD_REGS],
        };
        let frame = encode_hvf_snapshot_frame(
            9,
            0x20,
            test_layout(),
            b"devices",
            b"gic",
            std::slice::from_ref(&state),
            b"digest",
        )
        .unwrap();
        let header = mvm_core::snapshot_frame::parse_header(&frame).unwrap();
        assert_eq!(header.arch, GuestArch::Aarch64);
        assert_eq!(header.backend_kind, 9);
        assert_eq!(header.flags, 0x20);
        let entries = mvm_core::snapshot_frame::parse_sections(&frame).unwrap();
        assert_eq!(entries[0].data(&frame), test_layout().encode());
        assert_eq!(entries[1].data(&frame), b"devices");
        assert_eq!(entries[2].data(&frame), b"gic");
        assert_eq!(
            HvfVcpuState::decode(entries[3].data(&frame)).unwrap(),
            state
        );
        assert_eq!(entries[4].data(&frame), b"digest");
    }

    #[test]
    fn complete_frame_parser_requires_exact_backend_and_ram_shape() {
        let state = HvfVcpuState {
            x: [7; 31],
            pc: 0x8000,
            cpsr: 0x3c5,
            sys: [0; SNAPSHOT_SYS_REGS.len()],
            extra_sys: [0; SNAPSHOT_EXTRA_SYS_REGS.len()],
            gic_icc: [0; SNAPSHOT_GIC_ICC_REGS.len()],
            fpcr: 0,
            fpsr: 0,
            simd: [[0; 16]; VCPU_SIMD_REGS],
        };
        let frame = encode_hvf_snapshot_frame(
            9,
            0x20,
            test_layout(),
            b"devices",
            b"gic",
            std::slice::from_ref(&state),
            b"digest",
        )
        .unwrap();
        let parsed = parse_hvf_snapshot_frame(&frame, 9, TEST_RAM_LEN).unwrap();
        assert_eq!(parsed.ram, test_layout());
        assert_eq!(parsed.devices, b"devices");
        assert_eq!(parsed.gic, b"gic");
        assert_eq!(parsed.vcpus, vec![state]);
        assert_eq!(parsed.artifact_digests, b"digest");
        assert!(matches!(
            parse_hvf_snapshot_frame(&frame, 8, TEST_RAM_LEN),
            Err(HvfSnapshotError::BackendMismatch {
                expected: 8,
                actual: 9
            })
        ));
        assert!(matches!(
            parse_hvf_snapshot_frame(&frame, 9, TEST_RAM_LEN + HVF_PAGE_SIZE),
            Err(HvfSnapshotError::RamLength {
                expected,
                actual: TEST_RAM_LEN,
            }) if expected == TEST_RAM_LEN + HVF_PAGE_SIZE
        ));
    }

    /// One CPU's register state, distinguishable per CPU by the caller.
    fn sample_state() -> HvfVcpuState {
        HvfVcpuState {
            x: [7; 31],
            pc: 0x8000,
            cpsr: 0x3c5,
            sys: [0; SNAPSHOT_SYS_REGS.len()],
            extra_sys: [0; SNAPSHOT_EXTRA_SYS_REGS.len()],
            gic_icc: [0; SNAPSHOT_GIC_ICC_REGS.len()],
            fpcr: 0,
            fpsr: 0,
            simd: [[0; 16]; VCPU_SIMD_REGS],
        }
    }

    /// A machine's every CPU survives a frame round-trip, in CPU order.
    ///
    /// Order is the payload: a restore hands slot *n* to CPU *n*, so a frame
    /// that reordered them would resume each CPU on another's registers —
    /// stacks, per-CPU pointers and all — inside a RAM image that says
    /// otherwise.
    #[test]
    fn every_vcpu_survives_the_frame_in_cpu_order() {
        let states: Vec<HvfVcpuState> = (0..4u64)
            .map(|cpu| {
                let mut state = sample_state();
                state.pc = 0x8100_0000 + cpu;
                state.x[0] = 0xC0FFEE00 + cpu;
                state
            })
            .collect();

        let frame = encode_hvf_snapshot_frame(
            9,
            0x20,
            test_layout(),
            b"devices",
            b"gic",
            &states,
            b"digest",
        )
        .unwrap();
        let parsed = parse_hvf_snapshot_frame(&frame, 9, TEST_RAM_LEN).unwrap();

        assert_eq!(parsed.vcpus, states);
    }

    #[test]
    fn validated_frame_reports_its_vcpu_count_before_restore() {
        let states = vec![sample_state(), sample_state()];
        let frame = encode_hvf_snapshot_frame(
            HVF_SNAPSHOT_BACKEND_KIND,
            0,
            test_layout(),
            b"devices",
            b"gic",
            &states,
            b"digest",
        )
        .unwrap();

        assert_eq!(hvf_snapshot_vcpu_count(&frame, TEST_RAM_LEN).unwrap(), 2);
    }

    /// A vCPU section that is not a whole number of records is refused.
    ///
    /// The CPU count is derived from the section length, so a truncated
    /// trailing record would otherwise silently drop a CPU — and the child
    /// would boot with fewer CPUs than the guest inside its own restored memory
    /// believes it has.
    #[test]
    fn a_partial_vcpu_record_is_refused_rather_than_truncated() {
        let state = sample_state();
        let mut bytes = state.encode().to_vec();
        bytes.extend_from_slice(&state.encode()[..VCPU_STATE_LEN - 1]);

        let error = decode_vcpu_states(&bytes).unwrap_err();
        assert!(
            matches!(error, HvfSnapshotError::Vcpu(_)),
            "expected a vCPU-section error, got {error:?}"
        );
    }

    /// A frame carrying no CPU at all is refused.
    ///
    /// There is no such machine. Accepting it would hand the restore an empty
    /// list and leave the boot CPU resuming whatever the fresh vCPU happened to
    /// hold.
    #[test]
    fn a_vcpu_section_with_no_cpus_is_refused() {
        assert!(decode_vcpu_states(&[]).is_err());
    }

    #[test]
    fn complete_frame_parser_rejects_duplicate_required_sections() {
        let state = HvfVcpuState {
            x: [0; 31],
            pc: 0,
            cpsr: 0,
            sys: [0; SNAPSHOT_SYS_REGS.len()],
            extra_sys: [0; SNAPSHOT_EXTRA_SYS_REGS.len()],
            gic_icc: [0; SNAPSHOT_GIC_ICC_REGS.len()],
            fpcr: 0,
            fpsr: 0,
            simd: [[0; 16]; VCPU_SIMD_REGS],
        };
        let vcpu = state.encode();
        let layout = test_layout().encode();
        let frame = mvm_core::snapshot_frame::encode_frame(
            GuestArch::Aarch64,
            9,
            0,
            &[
                SnapshotSection {
                    kind: SectionKind::Unknown(HVF_RAM_LAYOUT_SECTION_KIND),
                    data: &layout,
                },
                SnapshotSection {
                    kind: SectionKind::Unknown(HVF_RAM_LAYOUT_SECTION_KIND),
                    data: &layout,
                },
                SnapshotSection {
                    kind: SectionKind::Devices,
                    data: b"devices",
                },
                SnapshotSection {
                    kind: SectionKind::Unknown(HVF_GIC_STATE_SECTION_KIND),
                    data: b"gic",
                },
                SnapshotSection {
                    kind: SectionKind::Vcpu,
                    data: &vcpu,
                },
                SnapshotSection {
                    kind: SectionKind::ArtifactDigests,
                    data: b"digest",
                },
            ],
        )
        .unwrap();
        assert!(matches!(
            parse_hvf_snapshot_frame(&frame, 9, TEST_RAM_LEN),
            Err(HvfSnapshotError::DuplicateSection(SectionKind::Unknown(
                HVF_RAM_LAYOUT_SECTION_KIND
            )))
        ));
    }

    #[test]
    fn complete_frame_parser_requires_gic_state() {
        let state = sample_state().encode();
        let layout = test_layout().encode();
        let frame = mvm_core::snapshot_frame::encode_frame(
            GuestArch::Aarch64,
            9,
            0,
            &[
                SnapshotSection {
                    kind: SectionKind::Unknown(HVF_RAM_LAYOUT_SECTION_KIND),
                    data: &layout,
                },
                SnapshotSection {
                    kind: SectionKind::Devices,
                    data: b"devices",
                },
                SnapshotSection {
                    kind: SectionKind::Vcpu,
                    data: &state,
                },
                SnapshotSection {
                    kind: SectionKind::ArtifactDigests,
                    data: b"digest",
                },
            ],
        )
        .expect("encode frame");

        assert!(matches!(
            parse_hvf_snapshot_frame(&frame, 9, TEST_RAM_LEN),
            Err(HvfSnapshotError::MissingSection(SectionKind::Unknown(
                HVF_GIC_STATE_SECTION_KIND
            )))
        ));
    }

    #[test]
    fn ram_layout_round_trips_through_its_encoding() {
        let layout = RamLayout {
            file_offset: HVF_PAGE_SIZE as u64 * 3,
            len: HVF_PAGE_SIZE as u64 * 64,
            page_size: HVF_PAGE_SIZE as u32,
        };
        assert_eq!(RamLayout::decode(&layout.encode()).unwrap(), layout);
        assert_eq!(
            RamLayout::decode(&layout.encode()[..RAM_LAYOUT_LEN - 1]),
            Err(RamLayoutError::Encoding {
                len: RAM_LAYOUT_LEN - 1
            })
        );
    }

    #[test]
    fn a_whole_file_layout_starts_at_zero_on_a_page_boundary() {
        let layout = RamLayout::whole_file(TEST_RAM_LEN);
        assert_eq!(layout.file_offset, 0);
        assert_eq!(layout.len, TEST_RAM_LEN as u64);
        assert_eq!(layout.file_end().unwrap(), TEST_RAM_LEN as u64);
        layout.validate(TEST_RAM_LEN).unwrap();
    }

    /// Every edge that would make the mapping replace a partial page, or read
    /// past a representable file offset, is refused before anything is mapped.
    #[test]
    fn ram_layout_refuses_ranges_that_cannot_be_mapped_whole() {
        let page = HVF_PAGE_SIZE as u64;
        let base = test_layout();
        let refused = |layout: RamLayout| layout.validate(TEST_RAM_LEN).unwrap_err();

        assert_eq!(
            refused(RamLayout {
                page_size: 4096,
                ..base
            }),
            HvfSnapshotError::RamLayout(RamLayoutError::PageSize {
                expected: HVF_PAGE_SIZE as u32,
                actual: 4096
            })
        );
        assert_eq!(
            refused(RamLayout {
                file_offset: page + 1,
                ..base
            }),
            HvfSnapshotError::RamLayout(RamLayoutError::MisalignedOffset { offset: page + 1 })
        );
        assert_eq!(
            refused(RamLayout {
                len: base.len - 1,
                ..base
            }),
            HvfSnapshotError::RamLayout(RamLayoutError::MisalignedLength { len: base.len - 1 })
        );
        assert_eq!(
            refused(RamLayout {
                file_offset: (u64::MAX / page) * page,
                ..base
            }),
            HvfSnapshotError::RamLayout(RamLayoutError::Overflow)
        );
        assert!(matches!(
            refused(RamLayout {
                len: base.len + page,
                ..base
            }),
            HvfSnapshotError::RamLength { .. }
        ));
    }

    /// A frame captured before RAM moved out of it is refused by name, so an old
    /// checkpoint reads as old rather than as corrupt.
    #[test]
    fn a_frame_carrying_inline_ram_is_refused_as_the_old_format() {
        let state = sample_state().encode();
        let frame = mvm_core::snapshot_frame::encode_frame(
            GuestArch::Aarch64,
            HVF_SNAPSHOT_BACKEND_KIND,
            0,
            &[
                SnapshotSection {
                    kind: SectionKind::Ram,
                    data: &[0_u8; TEST_RAM_LEN],
                },
                SnapshotSection {
                    kind: SectionKind::Devices,
                    data: b"devices",
                },
                SnapshotSection {
                    kind: SectionKind::Unknown(HVF_GIC_STATE_SECTION_KIND),
                    data: b"gic",
                },
                SnapshotSection {
                    kind: SectionKind::Vcpu,
                    data: &state,
                },
                SnapshotSection {
                    kind: SectionKind::ArtifactDigests,
                    data: b"digest",
                },
            ],
        )
        .unwrap();

        let error =
            parse_hvf_snapshot_frame(&frame, HVF_SNAPSHOT_BACKEND_KIND, TEST_RAM_LEN).unwrap_err();
        assert_eq!(error, HvfSnapshotError::InlineRam);
        assert!(error.to_string().contains("capture the checkpoint again"));
    }

    /// The frame no longer grows with guest memory: a 4 GiB machine's frame is
    /// the same size as a two-page one.
    #[test]
    fn the_frame_size_does_not_depend_on_guest_ram() {
        let states = [sample_state()];
        let small = encode_hvf_snapshot_frame(
            HVF_SNAPSHOT_BACKEND_KIND,
            0,
            test_layout(),
            b"devices",
            b"gic",
            &states,
            b"",
        )
        .unwrap();
        let large = encode_hvf_snapshot_frame(
            HVF_SNAPSHOT_BACKEND_KIND,
            0,
            RamLayout::whole_file(4 << 30),
            b"devices",
            b"gic",
            &states,
            b"",
        )
        .unwrap();
        assert_eq!(small.len(), large.len());
    }

    #[test]
    fn a_frame_without_a_ram_layout_is_refused() {
        let state = sample_state().encode();
        let frame = mvm_core::snapshot_frame::encode_frame(
            GuestArch::Aarch64,
            HVF_SNAPSHOT_BACKEND_KIND,
            0,
            &[
                SnapshotSection {
                    kind: SectionKind::Devices,
                    data: b"devices",
                },
                SnapshotSection {
                    kind: SectionKind::Unknown(HVF_GIC_STATE_SECTION_KIND),
                    data: b"gic",
                },
                SnapshotSection {
                    kind: SectionKind::Vcpu,
                    data: &state,
                },
                SnapshotSection {
                    kind: SectionKind::ArtifactDigests,
                    data: b"digest",
                },
            ],
        )
        .unwrap();
        assert_eq!(
            parse_hvf_snapshot_frame(&frame, HVF_SNAPSHOT_BACKEND_KIND, TEST_RAM_LEN).unwrap_err(),
            HvfSnapshotError::MissingSection(SectionKind::Unknown(HVF_RAM_LAYOUT_SECTION_KIND))
        );
    }

    /// Capture, verify, map: a restored guest sees exactly the bytes the
    /// capture wrote, even when the checkpoint file is edited between
    /// verification and mapping — because what is mapped is the unlinked
    /// clone, a different file from the checkpoint.
    ///
    /// It deliberately asserts nothing about an edit made *after* mapping. On
    /// macOS a private mapping has not been observed to pick up later writes
    /// to its file, so such an assertion would pass with or without the clone
    /// and prove nothing; the file identity checked here is what protects.
    #[test]
    fn a_captured_image_round_trips_through_verification_into_a_private_mapping() {
        use mvm_vmm::host::restore_image::VerifiedRestoreFile;
        use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        // The verification requires a directory no other user can reach, and
        // a bare tempdir is not guaranteed to be owner-only.
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut captured = GuestRam::new(TEST_RAM_LEN).unwrap();
        captured.copy_at(0, b"first page").unwrap();
        captured.copy_at(HVF_PAGE_SIZE, b"second page").unwrap();
        let expected = captured.snapshot_bytes();

        let ram_path = dir.path().join("memory.bin");
        let layout = write_ram_image(&captured, &ram_path).unwrap();
        assert_eq!(layout, RamLayout::whole_file(TEST_RAM_LEN));
        let frame = encode_hvf_snapshot_frame(
            HVF_SNAPSHOT_BACKEND_KIND,
            0,
            layout,
            b"devices",
            b"gic",
            &[sample_state()],
            b"",
        )
        .unwrap();
        let frame_path = dir.path().join("memory.bin.hvf-frame");
        std::fs::write(&frame_path, &frame).unwrap();

        let verified = |path: &std::path::Path| {
            let digest = mvm_core::crypto::image_verify::sha256_file(path).unwrap();
            VerifiedRestoreFile::prepare(path, &state, &digest)
                .unwrap()
                .into_file()
        };
        let image = RestoreImage {
            ram: verified(&ram_path),
            frame: verified(&frame_path),
        };

        let tamper = |byte: u8| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&ram_path)
                .unwrap()
                .write_all_at(&vec![byte; HVF_PAGE_SIZE], 0)
                .unwrap();
        };
        let source = std::fs::metadata(&ram_path).unwrap();
        let mapped = image.ram.metadata().unwrap();
        assert_eq!(mapped.nlink(), 0, "the mapped file has no name left");
        assert_ne!(
            (mapped.dev(), mapped.ino()),
            (source.dev(), source.ino()),
            "the mapped file is the clone, not the checkpoint"
        );

        tamper(0xee);
        let mut restored = GuestRam::new(TEST_RAM_LEN).unwrap();
        assert_eq!(map_restore_image(&image, &mut restored).unwrap(), frame);
        let regions = restored.backing_regions(0);
        assert_eq!(regions.len(), 1, "{regions:?}");
        assert_eq!(
            regions[0].backing,
            mvm_vmm::vmm::virtio_balloon::RamBacking::PrivateFile
        );
        assert_eq!(
            restored.snapshot_bytes(),
            expected,
            "an edit to the checkpoint after verification must not reach the guest"
        );
    }
}
