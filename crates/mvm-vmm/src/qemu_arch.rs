//! Host-architecture-specific QEMU platform defaults shared by every QEMU
//! launch path.

/// QEMU machine type required by the host architecture.
///
/// `qemu-system-aarch64` has no default machine and refuses to start unless
/// one is selected. The x86_64 system emulator retains its established
/// default machine when the argument is omitted.
#[must_use]
pub fn machine_for_arch(arch: &str) -> Option<&'static str> {
    match arch {
        "aarch64" => Some("virt"),
        "x86_64" => None,
        _ => None,
    }
}

/// Serial console device exposed by QEMU's machine for the host architecture.
#[must_use]
pub fn serial_console_for_arch(arch: &str) -> &'static str {
    match arch {
        "aarch64" => "ttyAMA0",
        _ => "ttyS0",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aarch64_requires_virt_and_uses_pl011() {
        assert_eq!(machine_for_arch("aarch64"), Some("virt"));
        assert_eq!(serial_console_for_arch("aarch64"), "ttyAMA0");
    }

    #[test]
    fn x86_64_keeps_the_default_machine_and_uart() {
        assert_eq!(machine_for_arch("x86_64"), None);
        assert_eq!(serial_console_for_arch("x86_64"), "ttyS0");
    }
}
