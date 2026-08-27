//! HVF state codecs for the in-house snapshot frame.
//!
//! The codec is deliberately limited to architecturally visible state that
//! this backend can currently read and write: the 31 AArch64 general-purpose
//! registers, PC, and CPSR. Device state and RAM are carried by separate
//! sections in [`mvm_core::snapshot_frame`]; capability admission remains off
//! until the live pause/serialize/restore loop owns all of those sections.

use super::HvfError;
use super::guest_ram::GuestRam;
use super::hv_impl::HvfVcpu;
use crate::vmm::device_state::{
    DeviceStateError, SnapshotDeviceState, capture_device_states, restore_device_states,
};
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
/// Number of serialized 64-bit AArch64 register words.
pub const VCPU_STATE_WORDS: usize = 33 + SNAPSHOT_SYS_REGS.len();
/// Fixed encoded length of [`HvfVcpuState`].
pub const VCPU_STATE_LEN: usize = VCPU_STATE_WORDS * 8;
/// Stable frame identity for the first-party HVF device model.
pub const HVF_SNAPSHOT_BACKEND_KIND: u8 = 1;

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
        }
    }
}

impl std::error::Error for HvfSnapshotError {}

impl From<FrameError> for HvfSnapshotError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
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
    /// Complete guest RAM contents.
    pub ram: &'a [u8],
    /// Versioned device-state container.
    pub devices: &'a [u8],
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
        Ok(Self {
            x,
            pc: read_word(bytes, 31)?,
            cpsr: read_word(bytes, 32)?,
            sys,
        })
    }
}

/// Assemble the four sections owned by an HVF snapshot producer. The device
/// and artifact payloads are supplied by their respective serializers; this
/// function only makes their placement and frame metadata unambiguous.
pub fn encode_hvf_snapshot_frame(
    backend_kind: u8,
    flags: u32,
    ram: &[u8],
    devices: &[u8],
    vcpus: &[HvfVcpuState],
    artifact_digests: &[u8],
) -> Result<Vec<u8>, FrameError> {
    // Every CPU's state, concatenated in CPU order. Fixed-width records, so the
    // count is the section length over the record length and no separate field
    // can disagree with the payload.
    let vcpu_bytes: Vec<u8> = vcpus.iter().flat_map(|state| state.encode()).collect();
    mvm_core::snapshot_frame::encode_frame(
        GuestArch::Aarch64,
        backend_kind,
        flags,
        &[
            SnapshotSection {
                kind: SectionKind::Ram,
                data: ram,
            },
            SnapshotSection {
                kind: SectionKind::Devices,
                data: devices,
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

/// Capture all state owned by the in-process HVF VMM into one bounded frame.
///
/// The caller must already have paused guest execution. This function does not
/// claim or infer a pause boundary; it only combines the individual state
/// codecs and leaves capability admission to the backend owner.
pub fn capture_hvf_snapshot_frame(
    backend_kind: u8,
    flags: u32,
    ram: &GuestRam,
    vcpu: &HvfVcpu,
    devices: &[&dyn SnapshotDeviceState],
    artifact_digests: &[u8],
) -> Result<Vec<u8>, HvfSnapshotError> {
    let vcpu_state = vcpu.capture_state().map_err(HvfSnapshotError::Vcpu)?;
    let device_state = capture_device_states(devices)?;
    encode_hvf_snapshot_frame(
        backend_kind,
        flags,
        &ram.snapshot_bytes(),
        &device_state,
        std::slice::from_ref(&vcpu_state),
        artifact_digests,
    )
    .map_err(HvfSnapshotError::Frame)
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
    let mut vcpu = None;
    let mut artifact_digests = None;
    for entry in parse_sections(frame)? {
        let slot = match entry.kind {
            SectionKind::Ram => &mut ram,
            SectionKind::Devices => &mut devices,
            SectionKind::Vcpu => &mut vcpu,
            SectionKind::ArtifactDigests => &mut artifact_digests,
            SectionKind::Unknown(_) => continue,
        };
        if slot.is_some() {
            return Err(HvfSnapshotError::DuplicateSection(entry.kind));
        }
        *slot = Some(entry.data(frame));
    }

    let ram = ram.ok_or(HvfSnapshotError::MissingSection(SectionKind::Ram))?;
    if ram.len() != expected_ram_len {
        return Err(HvfSnapshotError::RamLength {
            expected: expected_ram_len,
            actual: ram.len(),
        });
    }
    let devices = devices.ok_or(HvfSnapshotError::MissingSection(SectionKind::Devices))?;
    let vcpu_bytes = vcpu.ok_or(HvfSnapshotError::MissingSection(SectionKind::Vcpu))?;
    let artifact_digests = artifact_digests.ok_or(HvfSnapshotError::MissingSection(
        SectionKind::ArtifactDigests,
    ))?;

    Ok(ParsedHvfSnapshot {
        ram,
        devices,
        vcpus: decode_vcpu_states(vcpu_bytes)?,
        artifact_digests,
    })
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

/// Restore a validated frame into an already-paused HVF target.
///
/// Frame parsing and vCPU decoding happen before RAM or device mutation. The
/// target remains paused; the caller owns the final resume decision and any
/// host-channel rebind required by the restored device topology.
/// Restores the boot CPU and returns every secondary's state for its own
/// thread to apply.
///
/// The secondaries are not restored here because HVF only lets a vCPU's
/// registers be written from the thread that created it. This call runs on the
/// boot CPU's thread, so it restores CPU 0 and hands the rest back for the
/// threads that own them.
pub fn restore_hvf_snapshot_frame(
    frame: &[u8],
    expected_backend_kind: u8,
    ram: &mut GuestRam,
    vcpu: &HvfVcpu,
    devices: &mut [&mut dyn SnapshotDeviceState],
) -> Result<Vec<HvfVcpuState>, HvfSnapshotError> {
    let parsed = parse_hvf_snapshot_frame(frame, expected_backend_kind, ram.len())?;
    let mut targets = devices
        .iter_mut()
        .map(|device| &mut **device as &mut dyn SnapshotDeviceState)
        .collect::<Vec<_>>();
    // Validate the device container and all record-to-device matches before
    // copying RAM. Individual device codecs validate their payload before
    // mutating their own registers.
    restore_device_states(&mut targets, parsed.devices)?;
    ram.restore_bytes(parsed.ram)
        .map_err(HvfSnapshotError::Vcpu)?;
    restore_boot_cpu_and_split(vcpu, parsed.vcpus)
}

/// Apply the boot CPU's state and return the secondaries' in CPU order.
fn restore_boot_cpu_and_split(
    vcpu: &HvfVcpu,
    mut states: Vec<HvfVcpuState>,
) -> Result<Vec<HvfVcpuState>, HvfSnapshotError> {
    // `decode_vcpu_states` refuses an empty section, so there is always a boot
    // CPU here.
    let secondaries = states.split_off(1);
    let boot = states.remove(0);
    vcpu.restore_state(&boot).map_err(HvfSnapshotError::Vcpu)?;
    Ok(secondaries)
}

/// Restore only vCPU and deterministic device state from a frame whose RAM is
/// already privately mapped from the sibling raw-RAM file.
pub fn restore_hvf_snapshot_control(
    frame: &[u8],
    expected_ram_len: usize,
    vcpu: &HvfVcpu,
    devices: &mut [&mut dyn SnapshotDeviceState],
) -> Result<Vec<HvfVcpuState>, HvfSnapshotError> {
    let parsed = parse_hvf_snapshot_frame(frame, HVF_SNAPSHOT_BACKEND_KIND, expected_ram_len)?;
    restore_device_states(devices, parsed.devices)?;
    restore_boot_cpu_and_split(vcpu, parsed.vcpus)
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

    #[test]
    fn state_codec_roundtrips_all_registers() {
        let state = HvfVcpuState {
            x: core::array::from_fn(|index| 0x1000 + index as u64),
            pc: 0x4000,
            cpsr: 0x3c5,
            sys: core::array::from_fn(|index| index as u64),
        };
        let encoded = state.encode();
        assert_eq!(encoded.len(), VCPU_STATE_LEN);
        assert_eq!(HvfVcpuState::decode(&encoded).unwrap(), state);
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
        };
        let frame = encode_hvf_snapshot_frame(
            9,
            0x20,
            b"ram",
            b"devices",
            std::slice::from_ref(&state),
            b"digest",
        )
        .unwrap();
        let header = mvm_core::snapshot_frame::parse_header(&frame).unwrap();
        assert_eq!(header.arch, GuestArch::Aarch64);
        assert_eq!(header.backend_kind, 9);
        assert_eq!(header.flags, 0x20);
        let entries = mvm_core::snapshot_frame::parse_sections(&frame).unwrap();
        assert_eq!(entries[0].data(&frame), b"ram");
        assert_eq!(entries[1].data(&frame), b"devices");
        assert_eq!(
            HvfVcpuState::decode(entries[2].data(&frame)).unwrap(),
            state
        );
        assert_eq!(entries[3].data(&frame), b"digest");
    }

    #[test]
    fn complete_frame_parser_requires_exact_backend_and_ram_shape() {
        let state = HvfVcpuState {
            x: [7; 31],
            pc: 0x8000,
            cpsr: 0x3c5,
            sys: [0; SNAPSHOT_SYS_REGS.len()],
        };
        let frame = encode_hvf_snapshot_frame(
            9,
            0x20,
            b"ram",
            b"devices",
            std::slice::from_ref(&state),
            b"digest",
        )
        .unwrap();
        let parsed = parse_hvf_snapshot_frame(&frame, 9, 3).unwrap();
        assert_eq!(parsed.ram, b"ram");
        assert_eq!(parsed.devices, b"devices");
        assert_eq!(parsed.vcpus, vec![state]);
        assert_eq!(parsed.artifact_digests, b"digest");
        assert!(matches!(
            parse_hvf_snapshot_frame(&frame, 8, 3),
            Err(HvfSnapshotError::BackendMismatch {
                expected: 8,
                actual: 9
            })
        ));
        assert!(matches!(
            parse_hvf_snapshot_frame(&frame, 9, 4),
            Err(HvfSnapshotError::RamLength {
                expected: 4,
                actual: 3
            })
        ));
    }

    /// One CPU's register state, distinguishable per CPU by the caller.
    fn sample_state() -> HvfVcpuState {
        HvfVcpuState {
            x: [7; 31],
            pc: 0x8000,
            cpsr: 0x3c5,
            sys: [0; SNAPSHOT_SYS_REGS.len()],
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

        let frame =
            encode_hvf_snapshot_frame(9, 0x20, b"ram", b"devices", &states, b"digest").unwrap();
        let parsed = parse_hvf_snapshot_frame(&frame, 9, 3).unwrap();

        assert_eq!(parsed.vcpus, states);
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
        };
        let vcpu = state.encode();
        let frame = mvm_core::snapshot_frame::encode_frame(
            GuestArch::Aarch64,
            9,
            0,
            &[
                SnapshotSection {
                    kind: SectionKind::Ram,
                    data: b"ram",
                },
                SnapshotSection {
                    kind: SectionKind::Ram,
                    data: b"ram",
                },
                SnapshotSection {
                    kind: SectionKind::Devices,
                    data: b"devices",
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
            parse_hvf_snapshot_frame(&frame, 9, 3),
            Err(HvfSnapshotError::DuplicateSection(SectionKind::Ram))
        ));
    }
}
