//! Concrete [`mvm_vmm::driver::VmmDriver`] implementations.

pub mod fc;
pub mod hvf;
pub mod hvf_bootargs;
pub mod hvf_restore;
pub mod libkrun;
pub mod qemu;

pub mod hvf_process;
pub mod libkrun_process;
pub mod qemu_process;

pub use fc::FcDriver;
pub use hvf::HvfDriver;
pub use libkrun::LibkrunDriver;
pub use qemu::QemuDriver;

/// Host-dialable workload services. Guest-dialed and builder-only services
/// must never be exposed through a workload's host connection API.
fn host_dialable_port(port: u32) -> bool {
    use mvm_net::channel::GuestService;
    port == GuestService::MachineControl.port()
        || port == GuestService::Telemetry.port()
        || mvm_agentd::vsock::dev_console_data_ports().any(|allowed| allowed == port)
}

#[cfg(test)]
mod tests {
    use super::host_dialable_port;
    use mvm_net::channel::GuestService;

    #[test]
    fn host_dial_ports_exclude_guest_dialed_and_builder_services() {
        for port in 0..=u32::from(u16::MAX) {
            assert_eq!(
                host_dialable_port(port),
                port == GuestService::MachineControl.port()
                    || port == GuestService::Telemetry.port()
                    || (20001..=20128).contains(&port),
                "unexpected host-dial policy for port {port}"
            );
        }
        assert!(!host_dialable_port(u32::MAX));
    }
}
