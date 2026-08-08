//! Bounded device-state containers for snapshot frames.
//!
//! Device state is separate from guest RAM: it contains only the device-owned
//! control plane needed to resume a paused guest against already-bound backing
//! resources. Host handles, console transcripts, entropy bytes, and active
//! network sessions are not silently serialized.

use std::fmt;

const DEVICE_STATE_MAGIC: [u8; 8] = *b"MVMDVST1";
const DEVICE_STATE_VERSION: u16 = 0;
const HEADER_LEN: usize = 12;
const ENTRY_LEN: usize = 12;
/// Maximum number of device records in one device-state section.
pub const MAX_DEVICE_STATES: u64 = 64;
/// Maximum encoded size of the complete device-state section.
pub const MAX_DEVICE_STATE_BYTES: u64 = 1024 * 1024;

/// Device kinds understood by the in-house device model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// PL011 guest console.
    Pl011,
    /// virtio-mmio block device.
    VirtioBlk,
    /// virtio-mmio filesystem device.
    VirtioFs,
    /// virtio-mmio entropy device.
    VirtioRng,
    /// virtio-mmio socket transport.
    VirtioVsock,
    /// Future or unrecognized device kind.
    Unknown(u16),
}

impl DeviceKind {
    fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Pl011,
            2 => Self::VirtioBlk,
            3 => Self::VirtioFs,
            4 => Self::VirtioRng,
            5 => Self::VirtioVsock,
            _ => Self::Unknown(value),
        }
    }

    const fn to_u16(self) -> u16 {
        match self {
            Self::Pl011 => 1,
            Self::VirtioBlk => 2,
            Self::VirtioFs => 3,
            Self::VirtioRng => 4,
            Self::VirtioVsock => 5,
            Self::Unknown(value) => value,
        }
    }
}

/// Why a device-state section could not be encoded or restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStateError {
    /// Input ended before the requested bytes were available.
    Truncated { need: usize, have: usize },
    /// The section magic did not match this format.
    BadMagic,
    /// The section version is not supported by this runtime.
    UnsupportedVersion(u16),
    /// The record count exceeded the hard ceiling.
    CountExceedsCap { value: u64, max: u64 },
    /// The encoded section exceeded the hard byte ceiling.
    SizeExceedsCap { value: u64, max: u64 },
    /// A record range was not contained by the input.
    RegionOutOfBounds {
        offset: usize,
        len: usize,
        total: usize,
    },
    /// A scalar state value was not valid for its device register model.
    InvalidValue {
        kind: DeviceKind,
        field: &'static str,
    },
    /// The section contained a device kind for which no restore target exists.
    UnknownDeviceKind(u16),
    /// A state payload had bytes after its defined fields.
    TrailingBytes { remaining: usize },
}

impl fmt::Display for DeviceStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "device state truncated: need {need} bytes, have {have}")
            }
            Self::BadMagic => write!(f, "invalid device state magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported device state version {version}")
            }
            Self::CountExceedsCap { value, max } => {
                write!(f, "device state count {value} exceeds cap {max}")
            }
            Self::SizeExceedsCap { value, max } => {
                write!(f, "device state size {value} exceeds cap {max}")
            }
            Self::RegionOutOfBounds { offset, len, total } => {
                write!(f, "device state region [{offset}, +{len}) exceeds {total}")
            }
            Self::InvalidValue { kind, field } => {
                write!(f, "invalid {kind:?} device state field {field}")
            }
            Self::UnknownDeviceKind(kind) => write!(f, "unknown device state kind {kind}"),
            Self::TrailingBytes { remaining } => {
                write!(f, "device state payload has {remaining} trailing bytes")
            }
        }
    }
}

impl std::error::Error for DeviceStateError {}

/// One serialized device payload supplied to [`encode_device_states`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceStateSection<'a> {
    /// Device discriminator.
    pub kind: DeviceKind,
    /// Device-specific versioned payload.
    pub data: &'a [u8],
}

/// One parsed device payload borrowed from an encoded section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedDeviceState<'a> {
    /// Device discriminator.
    pub kind: DeviceKind,
    /// Borrowed device-specific payload.
    pub data: &'a [u8],
}

/// Encode the device records that occupy the snapshot frame's devices section.
pub fn encode_device_states(
    sections: &[DeviceStateSection<'_>],
) -> Result<Vec<u8>, DeviceStateError> {
    let count = u64::try_from(sections.len()).map_err(|_| DeviceStateError::CountExceedsCap {
        value: u64::MAX,
        max: MAX_DEVICE_STATES,
    })?;
    if count > MAX_DEVICE_STATES {
        return Err(DeviceStateError::CountExceedsCap {
            value: count,
            max: MAX_DEVICE_STATES,
        });
    }
    let table_len = sections
        .len()
        .checked_mul(ENTRY_LEN)
        .and_then(|len| HEADER_LEN.checked_add(len))
        .ok_or(DeviceStateError::SizeExceedsCap {
            value: u64::MAX,
            max: MAX_DEVICE_STATE_BYTES,
        })?;
    let total_len = sections.iter().try_fold(table_len, |total, section| {
        total
            .checked_add(section.data.len())
            .ok_or(DeviceStateError::SizeExceedsCap {
                value: u64::MAX,
                max: MAX_DEVICE_STATE_BYTES,
            })
    })?;
    let total_len_u64 = u64::try_from(total_len).map_err(|_| DeviceStateError::SizeExceedsCap {
        value: u64::MAX,
        max: MAX_DEVICE_STATE_BYTES,
    })?;
    if total_len_u64 > MAX_DEVICE_STATE_BYTES {
        return Err(DeviceStateError::SizeExceedsCap {
            value: total_len_u64,
            max: MAX_DEVICE_STATE_BYTES,
        });
    }

    let count_u16 =
        u16::try_from(sections.len()).map_err(|_| DeviceStateError::CountExceedsCap {
            value: count,
            max: MAX_DEVICE_STATES,
        })?;
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&DEVICE_STATE_MAGIC);
    bytes.extend_from_slice(&DEVICE_STATE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&count_u16.to_le_bytes());
    let mut offset = u32::try_from(table_len).map_err(|_| DeviceStateError::SizeExceedsCap {
        value: total_len_u64,
        max: MAX_DEVICE_STATE_BYTES,
    })?;
    for section in sections {
        let len =
            u32::try_from(section.data.len()).map_err(|_| DeviceStateError::SizeExceedsCap {
                value: u64::try_from(section.data.len()).unwrap_or(u64::MAX),
                max: MAX_DEVICE_STATE_BYTES,
            })?;
        bytes.extend_from_slice(&section.kind.to_u16().to_le_bytes());
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        offset = offset
            .checked_add(len)
            .ok_or(DeviceStateError::SizeExceedsCap {
                value: total_len_u64,
                max: MAX_DEVICE_STATE_BYTES,
            })?;
    }
    for section in sections {
        bytes.extend_from_slice(section.data);
    }
    Ok(bytes)
}

/// Parse and bounds-check the device records in an encoded section.
pub fn parse_device_states(bytes: &[u8]) -> Result<Vec<ParsedDeviceState<'_>>, DeviceStateError> {
    let total = bytes.len();
    if total > usize::try_from(MAX_DEVICE_STATE_BYTES).unwrap_or(usize::MAX) {
        return Err(DeviceStateError::SizeExceedsCap {
            value: u64::try_from(total).unwrap_or(u64::MAX),
            max: MAX_DEVICE_STATE_BYTES,
        });
    }
    if total < HEADER_LEN {
        return Err(DeviceStateError::Truncated {
            need: HEADER_LEN,
            have: total,
        });
    }
    if bytes[..8] != DEVICE_STATE_MAGIC {
        return Err(DeviceStateError::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != DEVICE_STATE_VERSION {
        return Err(DeviceStateError::UnsupportedVersion(version));
    }
    let count = usize::from(u16::from_le_bytes([bytes[10], bytes[11]]));
    if u64::try_from(count).unwrap_or(u64::MAX) > MAX_DEVICE_STATES {
        return Err(DeviceStateError::CountExceedsCap {
            value: u64::try_from(count).unwrap_or(u64::MAX),
            max: MAX_DEVICE_STATES,
        });
    }
    let table_len = count
        .checked_mul(ENTRY_LEN)
        .and_then(|len| HEADER_LEN.checked_add(len))
        .ok_or(DeviceStateError::RegionOutOfBounds {
            offset: HEADER_LEN,
            len: usize::MAX,
            total,
        })?;
    if table_len > total {
        return Err(DeviceStateError::RegionOutOfBounds {
            offset: HEADER_LEN,
            len: table_len - HEADER_LEN,
            total,
        });
    }
    let mut parsed = Vec::with_capacity(count);
    for index in 0..count {
        let at = HEADER_LEN + index * ENTRY_LEN;
        let kind = DeviceKind::from_u16(u16::from_le_bytes([bytes[at], bytes[at + 1]]));
        let offset_u32 = u32::from_le_bytes(bytes[at + 2..at + 6].try_into().map_err(|_| {
            DeviceStateError::Truncated {
                need: at + 6,
                have: total,
            }
        })?);
        let offset =
            usize::try_from(offset_u32).map_err(|_| DeviceStateError::RegionOutOfBounds {
                offset: usize::MAX,
                len: 0,
                total,
            })?;
        let len_u32 = u32::from_le_bytes(bytes[at + 6..at + 10].try_into().map_err(|_| {
            DeviceStateError::Truncated {
                need: at + 10,
                have: total,
            }
        })?);
        let len = usize::try_from(len_u32).map_err(|_| DeviceStateError::RegionOutOfBounds {
            offset,
            len: usize::MAX,
            total,
        })?;
        let end = offset
            .checked_add(len)
            .ok_or(DeviceStateError::RegionOutOfBounds { offset, len, total })?;
        if offset < table_len || end > total {
            return Err(DeviceStateError::RegionOutOfBounds { offset, len, total });
        }
        parsed.push(ParsedDeviceState {
            kind,
            data: &bytes[offset..end],
        });
    }
    Ok(parsed)
}

/// Small little-endian builder used by device-specific state codecs.
pub(crate) struct StateWriter(Vec<u8>);

impl StateWriter {
    pub(crate) fn new(version: u16) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&version.to_le_bytes());
        Self(bytes)
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Small little-endian reader used by device-specific state codecs.
pub(crate) struct StateReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StateReader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn version(&mut self, kind: DeviceKind) -> Result<u16, DeviceStateError> {
        self.u16(kind, "version")
    }

    pub(crate) fn u16(
        &mut self,
        kind: DeviceKind,
        field: &'static str,
    ) -> Result<u16, DeviceStateError> {
        let bytes = self.take(kind, field, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u32(
        &mut self,
        kind: DeviceKind,
        field: &'static str,
    ) -> Result<u32, DeviceStateError> {
        let bytes = self.take(kind, field, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
            DeviceStateError::Truncated {
                need: self.offset,
                have: self.bytes.len(),
            }
        })?))
    }

    pub(crate) fn u64(
        &mut self,
        kind: DeviceKind,
        field: &'static str,
    ) -> Result<u64, DeviceStateError> {
        let bytes = self.take(kind, field, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
            DeviceStateError::Truncated {
                need: self.offset,
                have: self.bytes.len(),
            }
        })?))
    }

    pub(crate) fn finish(self) -> Result<(), DeviceStateError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DeviceStateError::TrailingBytes {
                remaining: self.bytes.len() - self.offset,
            })
        }
    }

    fn take(
        &mut self,
        kind: DeviceKind,
        _field: &'static str,
        len: usize,
    ) -> Result<&'a [u8], DeviceStateError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DeviceStateError::InvalidValue {
                kind,
                field: "state length",
            })?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(DeviceStateError::Truncated {
                need: end,
                have: self.bytes.len(),
            })?;
        self.offset = end;
        Ok(bytes)
    }
}

/// Device-specific state capture and restore seam.
pub trait SnapshotDeviceState {
    /// Identify the device record kind.
    fn device_kind(&self) -> DeviceKind;
    /// Capture only deterministic device-owned control state.
    fn snapshot_state(&self) -> Result<Vec<u8>, DeviceStateError>;
    /// Validate and apply a previously captured control-state payload.
    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), DeviceStateError>;
}

/// Capture a set of device control states into one bounded devices section.
pub fn capture_device_states(
    devices: &[&dyn SnapshotDeviceState],
) -> Result<Vec<u8>, DeviceStateError> {
    let mut payloads = Vec::with_capacity(devices.len());
    for device in devices {
        payloads.push((device.device_kind(), device.snapshot_state()?));
    }
    let sections = payloads
        .iter()
        .map(|(kind, data)| DeviceStateSection { kind: *kind, data })
        .collect::<Vec<_>>();
    encode_device_states(&sections)
}

/// Restore records into matching device instances.
pub fn restore_device_states(
    devices: &mut [&mut dyn SnapshotDeviceState],
    bytes: &[u8],
) -> Result<(), DeviceStateError> {
    let records = parse_device_states(bytes)?;
    let mut matched = vec![false; devices.len()];
    for record in records {
        let Some((index, device)) = devices
            .iter_mut()
            .enumerate()
            .find(|(index, device)| !matched[*index] && device.device_kind() == record.kind)
        else {
            return Err(match record.kind {
                DeviceKind::Unknown(value) => DeviceStateError::UnknownDeviceKind(value),
                kind => DeviceStateError::InvalidValue {
                    kind,
                    field: "missing restore target",
                },
            });
        };
        device.restore_state(record.data)?;
        matched[index] = true;
    }
    if let Some(index) = matched.iter().position(|matched| !matched) {
        let kind = devices[index].device_kind();
        return Err(DeviceStateError::InvalidValue {
            kind,
            field: "missing snapshot record",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_roundtrips_multiple_records() {
        let encoded = encode_device_states(&[
            DeviceStateSection {
                kind: DeviceKind::Pl011,
                data: b"uart",
            },
            DeviceStateSection {
                kind: DeviceKind::VirtioBlk,
                data: b"block",
            },
        ])
        .unwrap();
        let records = parse_device_states(&encoded).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, DeviceKind::Pl011);
        assert_eq!(records[0].data, b"uart");
        assert_eq!(records[1].kind, DeviceKind::VirtioBlk);
        assert_eq!(records[1].data, b"block");
    }

    #[test]
    fn container_rejects_table_and_payload_out_of_bounds() {
        let mut encoded = vec![0u8; HEADER_LEN + ENTRY_LEN];
        encoded[..8].copy_from_slice(&DEVICE_STATE_MAGIC);
        encoded[8..10].copy_from_slice(&DEVICE_STATE_VERSION.to_le_bytes());
        encoded[10..12].copy_from_slice(&1u16.to_le_bytes());
        encoded[12..14].copy_from_slice(&DeviceKind::Pl011.to_u16().to_le_bytes());
        encoded[14..18].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(
            parse_device_states(&encoded),
            Err(DeviceStateError::RegionOutOfBounds { .. })
        ));
    }

    #[test]
    fn container_rejects_oversized_payload_before_encoding() {
        let oversized = vec![0u8; usize::try_from(MAX_DEVICE_STATE_BYTES).unwrap()];
        assert!(matches!(
            encode_device_states(&[DeviceStateSection {
                kind: DeviceKind::Pl011,
                data: &oversized,
            }]),
            Err(DeviceStateError::SizeExceedsCap { .. })
        ));
    }
}
