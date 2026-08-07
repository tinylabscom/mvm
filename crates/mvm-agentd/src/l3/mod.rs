//! The in-guest side of the L3 TUN-over-vsock tunnel.
//!
//! `mvm0` is a point-to-point TUN interface that terminates **only** in
//! this agent. Every packet the guest stack routes to it is serialized onto
//! a machine-scoped vsock data connection; nothing else in the guest can
//! reach the host network, because nothing else exists to reach it with —
//! this mode runs on backends that present no network device at all.
//!
//! See `specs/adrs/036-l3-tun-over-vsock.md`.

pub mod agent;
pub mod netcfg;
pub mod privdrop;
pub mod tun;

pub use agent::{AgentCounters, AgentError, AgentState, NetAgent};
pub use netcfg::{InterfaceConfigurator, InterfacePlan, Ipv6Plan, RecordingConfigurator};
pub use privdrop::{
    DropReport, PrivilegeDropper, RecordingPrivilegeDropper, SystemPrivilegeDropper,
    drop_privileges,
};
pub use tun::{MemoryTun, TunDevice, TunError};

#[cfg(target_os = "linux")]
pub use netcfg::KernelConfigurator;
#[cfg(target_os = "linux")]
pub use tun::LinuxTun;

#[cfg(test)]
mod contract_tests {
    use mvm_contract::l3::{GUEST_CMDLINE_FLAG, GUEST_READY_FILE};

    /// The guest init keys off this exact token, and the host emits it from
    /// the admitted plan. A rename on one side without the other is a guest
    /// that silently never starts its tunnel, so both ends read the same
    /// constant and this pins its value.
    #[test]
    fn the_cmdline_flag_is_the_one_both_ends_agree_on() {
        assert_eq!(GUEST_CMDLINE_FLAG, "mvm.l3=1");
        // A bare flag, not a key=value the guest would have to parse: the
        // init's `cmdline_has_flag` matches the whole token.
        assert!(!GUEST_CMDLINE_FLAG.contains(' '));
    }

    /// Readiness lives under `/run`, which is a tmpfs in every guest, so it
    /// cannot survive a reboot into a later boot that has no tunnel.
    #[test]
    fn the_readiness_file_lives_on_a_tmpfs() {
        assert_eq!(GUEST_READY_FILE, "/run/mvm/l3-ready");
        assert!(
            GUEST_READY_FILE.starts_with("/run/"),
            "a readiness marker on persistent storage would be inherited by a \
             later boot that has no tunnel"
        );
    }
}
