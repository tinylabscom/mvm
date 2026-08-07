//! What this surface can hold, and what that costs.
//!
//! Same discipline the packet datapath uses: every table has a cap, every
//! buffer has a cap, and the worst case is a named constant with an
//! assertion beside it — because a ceiling that has to be recomputed by
//! hand to be believed is one nobody re-checks.

use super::registry::REGISTRY_BYTES;

/// The largest request frame this surface reads.
///
/// A request names at most one machine, so it is small by construction.
/// The cap is enforced on the length prefix, before the body is allocated:
/// a peer claiming `u32::MAX` must cost nothing.
pub const MAX_REQUEST_FRAME_BYTES: usize = 8 * 1024;

/// Headroom for the response envelope around whatever the registry
/// contributes: the tag, the version, the node id, the unserved list, and
/// the forwarding report.
pub const RESPONSE_ENVELOPE_BYTES: usize = 4 * 1024;

/// The largest response frame this surface writes.
///
/// A listing is bounded by what the registry can hold, so this is that
/// bound plus the envelope around it. Enforced on write as well as derived
/// here, so a response that somehow exceeded it fails rather than ships.
pub const MAX_RESPONSE_FRAME_BYTES: usize = REGISTRY_BYTES + RESPONSE_ENVELOPE_BYTES;

/// Worst-case footprint of one node's control surface: the full registry,
/// plus the one request frame being read, plus the one response frame being
/// built.
///
/// An upper bound rather than an attainable state — the read and the write
/// buffer do not both hold their maximum at the same instant — summed
/// anyway, for the same reason the datapath's is.
///
/// As shipped: 2,109,440 bytes, 2.01 MiB.
pub const MEMORY_CEILING_BYTES: usize =
    REGISTRY_BYTES + MAX_REQUEST_FRAME_BYTES + MAX_RESPONSE_FRAME_BYTES;

#[cfg(test)]
mod tests {
    use super::super::registry::{MAX_RECORD_BYTES, MAX_REGISTERED_MACHINES};
    use super::*;

    /// Every term spelled out as a literal rather than recomputed from the
    /// expression the constant uses, so changing the formula has to be
    /// argued for here. The response frame is taken as the residual of the
    /// two that precede it: a term dropped from the sum then fails under
    /// its own name instead of as an anonymous shortfall in the total.
    #[test]
    fn the_node_control_memory_ceiling_is_what_we_claim() {
        assert_eq!(MAX_REGISTERED_MACHINES, 256);
        assert_eq!(MAX_RECORD_BYTES, 4096);
        // 256 machines at 4 KiB each.
        assert_eq!(REGISTRY_BYTES, 1_048_576);
        assert_eq!(MAX_REQUEST_FRAME_BYTES, 8_192);
        // The registry's own worst case plus 4 KiB of envelope.
        assert_eq!(
            MEMORY_CEILING_BYTES - REGISTRY_BYTES - MAX_REQUEST_FRAME_BYTES,
            MAX_RESPONSE_FRAME_BYTES
        );
        assert_eq!(MAX_RESPONSE_FRAME_BYTES, 1_048_576 + 4_096);
        assert_eq!(MEMORY_CEILING_BYTES, 1_048_576 + 8_192 + 1_052_672);
        // 2.01 MiB.
        assert_eq!(MEMORY_CEILING_BYTES, 2_109_440);
    }

    /// A listing of a full registry has to fit the frame it is written
    /// into, or the cap is a promise the surface cannot keep.
    #[test]
    fn a_full_registrys_listing_fits_the_response_frame() {
        const {
            assert!(
                MAX_REGISTERED_MACHINES * MAX_RECORD_BYTES + RESPONSE_ENVELOPE_BYTES
                    <= MAX_RESPONSE_FRAME_BYTES,
                "the response cap must admit a listing of a full registry"
            );
        };
    }
}
