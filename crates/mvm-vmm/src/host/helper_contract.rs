//! Shape pins of the host-helper config types this crate owns. Changing one
//! of those types means bumping `mvm_core::helper_contract`'s version.

/// FNV-1a over the canonical JSON of a fully populated
/// [`crate::host::hvf_supervisor::HvfSupervisorConfig`]. The shape-pin test
/// in that module recomputes this and compares — changing the struct's
/// fields without updating this pin (and bumping the contract version)
/// fails the test suite.
pub(crate) const HVF_CONFIG_SHAPE_HASH: u64 = 0xd635_aac1_89ac_99dc;

/// 64-bit FNV-1a, implemented inline so the shape pins have no dependency.
pub(crate) fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_matches_the_reference_value() {
        // Published FNV-1a test vector (from the FNV reference page).
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
