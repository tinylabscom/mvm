//! Stable host-side terminator port derivation for non-slot backends.
//!
//! The former Firecracker TAP redirect lived here. Only the port-number
//! allocator remains for the live libkrun endpoint configuration.

/// Per-slot terminator port base. The slot range is a stable numbering that
/// persisted endpoint metadata already refers to — changing it would move live
/// endpoints, so it stays. It no longer identifies a guest NIC.
pub const TERMINATOR_PORT_BASE: u16 = 18080;

/// Derive a terminator port from a slot index.
pub fn terminator_port_for(slot_index: u8) -> u16 {
    TERMINATOR_PORT_BASE + u16::from(slot_index)
}

/// Derive a stable terminator port for backends without a slot allocator.
pub fn terminator_port_for_vm_name(vm_name: &str) -> u16 {
    const NAME_PORT_BASE: u16 = TERMINATOR_PORT_BASE + 1024;
    const NAME_PORT_SPAN: u16 = 20_000;
    let hash = vm_name.bytes().fold(0x811c_9dc5_u32, |acc, b| {
        (acc ^ u32::from(b)).wrapping_mul(0x0100_0193)
    });
    NAME_PORT_BASE + (hash % u32::from(NAME_PORT_SPAN)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_ports_are_contiguous() {
        assert_eq!(terminator_port_for(0), TERMINATOR_PORT_BASE);
        assert_eq!(terminator_port_for(1), TERMINATOR_PORT_BASE + 1);
        assert_eq!(terminator_port_for(255), TERMINATOR_PORT_BASE + 255);
    }

    #[test]
    fn name_ports_are_stable_and_disjoint_from_slots() {
        let port = terminator_port_for_vm_name("workload-a");
        assert_eq!(port, terminator_port_for_vm_name("workload-a"));
        assert!(port >= TERMINATOR_PORT_BASE + 1024);
    }
}
