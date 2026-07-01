//! The backend descriptor registry.
//!
//! One declarative, compile-time table is the single source of truth for
//! backend discovery: selector + aliases, isolation tier, the per-VM marker
//! file, the started-VM probe order, and which listing/support surfaces each
//! backend participates in. `AnyBackend`, `mvmctl doctor`, and any backend
//! help/listing surface read from these descriptors rather than re-deriving
//! the facts locally.
//!
//! This is intentionally *not* a runtime plugin system: there is no dynamic
//! registration and no dylib discovery. The descriptor owns metadata and
//! constructor wiring; `VmBackend` owns runtime behavior; `AnyBackend` remains
//! the closed enum for the few intentionally backend-specific operations.

use crate::backend::{AnyBackend, BackendTier, FirecrackerBackend};
use crate::libkrun::LibkrunBackend;
use crate::mock::MockBackend;
use crate::qemu::QemuBackend;
use crate::vz::VzBackend;
use mvm_core::vm_backend::VmBackend;

/// A first-class, declarative description of one backend: its discovery
/// metadata and the surfaces it participates in. Behavioral policy lives in
/// `VmBackend`/`AnyBackend`, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendDescriptor {
    pub kind: BackendKind,
    pub selector: &'static str,
    pub aliases: &'static [&'static str],
    pub tier: BackendTier,
    pub marker_file: Option<&'static str>,
    pub started_vm_probe_order: Option<u8>,
    pub include_in_list_all: bool,
    pub include_in_balloon_support: bool,
    pub include_in_warm_start_support: bool,
}

impl BackendDescriptor {
    /// True when `selector` is this backend's canonical selector or one of its
    /// aliases.
    pub fn matches_selector(self, selector: &str) -> bool {
        self.selector == selector || self.aliases.contains(&selector)
    }

    /// Construct the `AnyBackend` enum variant this descriptor names.
    pub fn instantiate(self) -> AnyBackend {
        self.kind.instantiate()
    }

    /// Construct a shared `VmBackend` trait object directly from the
    /// descriptor, for consumers that only need the behavior surface and not
    /// enum-specific branching.
    pub fn instantiate_dyn(self) -> std::sync::Arc<dyn VmBackend> {
        self.kind.instantiate().into_dyn()
    }
}

macro_rules! backend_catalog {
    ($(
        {
            kind: $kind:ident,
            selector: $selector:literal,
            aliases: [$($alias:literal),* $(,)?],
            constructor: $constructor:expr,
            tier: $tier:ident,
            marker_file: $marker_file:expr,
            started_vm_probe_order: $started_vm_probe_order:expr,
            list_all: $list_all:expr,
            balloon_support: $balloon_support:expr,
            warm_start_support: $warm_start_support:expr
        }
    ),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum BackendKind {
            $($kind),*
        }

        pub const BACKEND_DESCRIPTORS: &[BackendDescriptor] = &[
            $(
                BackendDescriptor {
                    kind: BackendKind::$kind,
                    selector: $selector,
                    aliases: &[$($alias),*],
                    tier: BackendTier::$tier,
                    marker_file: $marker_file,
                    started_vm_probe_order: $started_vm_probe_order,
                    include_in_list_all: $list_all,
                    include_in_balloon_support: $balloon_support,
                    include_in_warm_start_support: $warm_start_support,
                },
            )*
        ];

        impl BackendKind {
            pub(crate) fn instantiate(self) -> AnyBackend {
                match self {
                    $(Self::$kind => $constructor),*
                }
            }
        }
    };
}

backend_catalog![
    {
        kind: Firecracker,
        selector: "firecracker",
        aliases: [],
        constructor: AnyBackend::Firecracker(FirecrackerBackend),
        tier: Tier1,
        marker_file: Some("fc.pid"),
        started_vm_probe_order: Some(3),
        list_all: true,
        balloon_support: true,
        warm_start_support: true
    },
    {
        kind: Libkrun,
        selector: "libkrun",
        aliases: ["krun"],
        constructor: AnyBackend::Libkrun(LibkrunBackend),
        tier: Tier2,
        marker_file: Some("libkrun.pid"),
        started_vm_probe_order: Some(2),
        list_all: true,
        balloon_support: true,
        warm_start_support: true
    },
    {
        kind: Vz,
        selector: "vz",
        aliases: ["virtualization"],
        constructor: AnyBackend::Vz(VzBackend),
        tier: Tier2,
        marker_file: Some("vz.pid"),
        started_vm_probe_order: Some(4),
        list_all: false,
        balloon_support: false,
        warm_start_support: true
    },
    {
        kind: Qemu,
        selector: "qemu",
        aliases: [],
        constructor: AnyBackend::Qemu(QemuBackend),
        tier: Tier2,
        marker_file: Some("qemu.pid"),
        started_vm_probe_order: Some(1),
        list_all: true,
        balloon_support: true,
        warm_start_support: true
    },
    {
        kind: Mock,
        selector: "mock",
        aliases: [],
        constructor: AnyBackend::Mock(MockBackend::new()),
        tier: Tier3,
        marker_file: None,
        started_vm_probe_order: None,
        list_all: false,
        balloon_support: false,
        warm_start_support: false
    },
    {
        kind: Hvf,
        selector: "hvf",
        aliases: ["hypervisor"],
        constructor: AnyBackend::Hvf(crate::hvf_backend::HvfBackend),
        tier: Tier2,
        marker_file: Some("hvf.pid"),
        started_vm_probe_order: Some(5),
        list_all: true,
        balloon_support: false,
        warm_start_support: false
    }
];

/// Every registered backend descriptor, in declaration order.
pub fn descriptors() -> &'static [BackendDescriptor] {
    BACKEND_DESCRIPTORS
}

/// The descriptor for a given backend kind. Panics only if the catalog is
/// internally inconsistent (every `BackendKind` is declared in the table).
pub fn descriptor(kind: BackendKind) -> &'static BackendDescriptor {
    BACKEND_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.kind == kind)
        .expect("backend kind must exist in the descriptor registry")
}

/// The descriptor whose canonical selector or alias matches `selector`.
pub fn descriptor_for_selector(selector: &str) -> Option<&'static BackendDescriptor> {
    BACKEND_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.matches_selector(selector))
}

/// The descriptor that owns the per-VM `marker_file`.
pub fn descriptor_for_marker_file(marker_file: &str) -> Option<&'static BackendDescriptor> {
    BACKEND_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.marker_file == Some(marker_file))
}

/// Descriptors that drop a per-VM marker file, ordered by their started-VM
/// probe priority so `for_started_vm` checks them deterministically.
pub fn started_vm_probe_descriptors() -> Vec<&'static BackendDescriptor> {
    let mut descriptors: Vec<_> = BACKEND_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.started_vm_probe_order.is_some())
        .collect();
    descriptors.sort_by_key(|descriptor| {
        descriptor
            .started_vm_probe_order
            .expect("started-vm probe descriptors must have a probe order")
    });
    descriptors
}

/// Descriptors included in the aggregate running-VM listing (`mvmctl ls`).
pub fn list_all_descriptors() -> impl Iterator<Item = &'static BackendDescriptor> {
    BACKEND_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.include_in_list_all)
}

/// Descriptors that report virtio-balloon support in `mvmctl doctor`.
pub fn balloon_support_descriptors() -> impl Iterator<Item = &'static BackendDescriptor> {
    BACKEND_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.include_in_balloon_support)
}

/// Descriptors that report warm-start support in `mvmctl doctor`.
pub fn warm_start_support_descriptors() -> impl Iterator<Item = &'static BackendDescriptor> {
    BACKEND_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.include_in_warm_start_support)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor-driven trait-object constructor must produce a backend
    /// behaviorally identical to the enum constructor for every registered
    /// backend — same name, capabilities, and security tier. This guards the
    /// macro wiring: a variant mapped to the wrong backend would diverge here.
    /// Every backend constructs without I/O, so the comparison is side-effect
    /// free.
    #[test]
    fn descriptor_dyn_construction_matches_enum_for_every_backend() {
        for descriptor in descriptors() {
            let via_enum = descriptor.instantiate();
            let via_dyn = descriptor.instantiate_dyn();
            assert_eq!(
                via_enum.name(),
                via_dyn.name(),
                "name mismatch for {:?}",
                descriptor.kind
            );
            assert_eq!(
                format!("{:?}", via_enum.capabilities()),
                format!("{:?}", via_dyn.capabilities()),
                "capabilities mismatch for {:?}",
                descriptor.kind
            );
            assert_eq!(
                via_enum.security_profile().tier,
                via_dyn.security_profile().tier,
                "tier mismatch for {:?}",
                descriptor.kind
            );
        }
    }

    fn selectors<'a>(it: impl Iterator<Item = &'a BackendDescriptor>) -> Vec<&'a str> {
        it.map(|descriptor| descriptor.selector).collect()
    }

    /// The descriptor-filtered surfaces feed user-visible ordering in
    /// `mvmctl doctor` (balloon + warm-start matrices), `mvmctl ls`
    /// (list-all), and the started-VM probe. Freeze those orders so a table
    /// reshuffle can't silently change what users see or the probe priority.
    #[test]
    fn descriptor_surface_ordering_is_frozen() {
        assert_eq!(
            selectors(balloon_support_descriptors()),
            ["firecracker", "libkrun", "qemu"]
        );
        assert_eq!(
            selectors(warm_start_support_descriptors()),
            ["firecracker", "libkrun", "vz", "qemu"]
        );
        assert_eq!(
            selectors(list_all_descriptors()),
            ["firecracker", "libkrun", "qemu", "hvf"]
        );
        // Started-VM probe is sorted by probe order, not declaration order.
        assert_eq!(
            selectors(started_vm_probe_descriptors().into_iter()),
            ["qemu", "libkrun", "firecracker", "vz", "hvf"]
        );
    }
}
