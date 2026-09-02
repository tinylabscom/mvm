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

use crate::apple_container_backend::AppleContainerBackend;
use crate::backend::{AnyBackend, BackendTier};
#[cfg(feature = "test-support")]
use crate::mock::MockBackend;
use crate::wasm_backend::WasmBackend;
use crate::web_linux_backend::WebLinuxBackend;
use mvm_core::vm_backend::VmBackend;

// `BackendKind` is defined in `mvm-core` alongside the `VmBackend` trait
// (`VmBackend::kind()` needs it in scope, and `mvm-core` has no `mvm-*`
// deps to reach up into this registry for it). Re-exported here so existing
// `catalog::BackendKind` call sites keep resolving.
pub use mvm_core::vm_backend::BackendKind;

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
    /// This backend boots a kernel it bundles itself (no on-disk kernel
    /// path to hash for a compat key). True only for libkrun today.
    pub bundled_kernel: bool,
    /// This backend needs the admitted plan JSON stashed to disk for its
    /// external-VMM bridge to read at spawn time, rather than taking it
    /// in-process. False for every runner-driven backend — the runner takes the
    /// plan in-process — so no CLI-selectable backend sets it today.
    pub needs_plan_json: bool,
    /// This backend runs real (non-mock, non-dev-substrate) workloads —
    /// the admitted plan is stashed for its gateway/bridge audit path.
    /// True for Firecracker, libkrun, and hvf; false for qemu (dev/test
    /// substrate, no bridge) and mock.
    pub is_workload: bool,
}

impl BackendDescriptor {
    /// True when `selector` is this backend's canonical selector or one of its
    /// aliases.
    pub fn matches_selector(self, selector: &str) -> bool {
        self.selector == selector || self.aliases.contains(&selector)
    }

    /// Construct the `AnyBackend` enum variant this descriptor names.
    pub fn instantiate(self) -> AnyBackend {
        instantiate_kind(self.kind)
    }

    /// Construct a shared `VmBackend` trait object directly from the
    /// descriptor, for consumers that only need the behavior surface and not
    /// enum-specific branching.
    pub fn instantiate_dyn(self) -> std::sync::Arc<dyn VmBackend> {
        instantiate_kind(self.kind).into_dyn()
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
            warm_start_support: $warm_start_support:expr,
            bundled_kernel: $bundled_kernel:expr,
            needs_plan_json: $needs_plan_json:expr,
            is_workload: $is_workload:expr
        }
    ),* $(,)?) => {
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
                    bundled_kernel: $bundled_kernel,
                    needs_plan_json: $needs_plan_json,
                    is_workload: $is_workload,
                },
            )*
        ];

        // `BackendKind` is a foreign type here (owned by `mvm-core`), so this
        // can't be an inherent `impl BackendKind` (orphan rule) — a free
        // function keeps the kind->constructor pairing generated from the
        // same per-entry `constructor` expression as the descriptor table.
        fn instantiate_kind(kind: BackendKind) -> AnyBackend {
            match kind {
                $(BackendKind::$kind => $constructor),*
            }
        }
    };
}

/// Construct the mock descriptor's `AnyBackend`. The descriptor row stays in
/// the catalog in every build (so `"mock"` keeps resolving as a recognised
/// selector — `mvmctl doctor`, the catalog-matrix test, and the generic
/// descriptor-driven consumers all still see it), but the mock backend
/// itself only exists behind `test-support`. Outside that feature this
/// falls back to the same default `instantiate_kind` would otherwise be
/// unable to express for a variant that doesn't compile in — callers that
/// need a hard refusal instead of this fallback use
/// [`AnyBackend::require_hypervisor_selectable`] ahead of resolution.
#[cfg(feature = "test-support")]
fn mock_constructor() -> AnyBackend {
    AnyBackend::Mock(MockBackend::new())
}

#[cfg(not(feature = "test-support"))]
fn mock_constructor() -> AnyBackend {
    AnyBackend::default_backend()
}

backend_catalog![
    {
        kind: Firecracker,
        selector: "firecracker",
        aliases: [],
        constructor: AnyBackend::Firecracker(crate::backend::fc_runner()),
        tier: Tier1,
        marker_file: Some("fc.pid"),
        started_vm_probe_order: Some(3),
        list_all: true,
        // Discovery metadata is retained for legacy filtered surfaces; the
        // recovery truth is `VmCapabilities` on the constructed backend.
        balloon_support: false,
        warm_start_support: false,
        bundled_kernel: false,
        needs_plan_json: false,
        is_workload: true
    },
    {
        kind: Libkrun,
        selector: "libkrun",
        aliases: ["krun"],
        constructor: AnyBackend::Libkrun(crate::backend::libkrun_runner()),
        tier: Tier2,
        marker_file: Some("libkrun.pid"),
        started_vm_probe_order: Some(2),
        list_all: true,
        // The raw libkrun shim has disk-only and standby primitives, but the
        // selectable workload runner does not expose those paths yet.
        balloon_support: false,
        warm_start_support: false,
        bundled_kernel: true,
        needs_plan_json: false,
        is_workload: true
    },
    {
        kind: Qemu,
        selector: "qemu",
        aliases: [],
        constructor: AnyBackend::Qemu(crate::backend::qemu_runner()),
        tier: Tier2,
        marker_file: Some("qemu.pid"),
        started_vm_probe_order: Some(1),
        list_all: true,
        balloon_support: true,
        warm_start_support: false,
        bundled_kernel: false,
        needs_plan_json: false,
        is_workload: false
    },
    {
        kind: Mock,
        selector: "mock",
        aliases: [],
        constructor: mock_constructor(),
        tier: Tier3,
        marker_file: None,
        started_vm_probe_order: None,
        list_all: false,
        balloon_support: false,
        warm_start_support: false,
        bundled_kernel: false,
        needs_plan_json: false,
        is_workload: false
    },
    {
        kind: Hvf,
        selector: "hvf",
        aliases: ["hypervisor"],
        constructor: AnyBackend::Hvf(crate::backend::hvf_runner()),
        tier: Tier2,
        marker_file: Some("hvf.pid"),
        started_vm_probe_order: Some(5),
        list_all: true,
        balloon_support: false,
        warm_start_support: false,
        bundled_kernel: false,
        needs_plan_json: false,
        is_workload: true
    },
    {
        kind: Wasm,
        selector: "wasm",
        aliases: [],
        constructor: AnyBackend::Wasm(WasmBackend::new()),
        tier: Tier3,
        // No pid-file lifecycle — a module runs to completion inside
        // `start` and leaves no long-lived host process behind.
        marker_file: None,
        started_vm_probe_order: None,
        list_all: true,
        balloon_support: false,
        warm_start_support: false,
        bundled_kernel: false,
        needs_plan_json: false,
        is_workload: true
    },
    {
        kind: AppleContainer,
        selector: "apple-container",
        aliases: ["container"],
        constructor: AnyBackend::AppleContainer(AppleContainerBackend::new()),
        tier: Tier2,
        // No marker of its own: this backend IS the HVF runner with a
        // substituted kernel, so its VMs carry the HVF supervisor's
        // `hvf.pid` marker, which the probe already maps to the HVF
        // descriptor (mechanically correct — same supervisor).
        marker_file: None,
        started_vm_probe_order: None,
        list_all: true,
        balloon_support: false,
        warm_start_support: false,
        bundled_kernel: false,
        needs_plan_json: false,
        is_workload: true
    },    {
        kind: WebLinux,
        selector: "web-linux",
        aliases: [],
        constructor: AnyBackend::WebLinux(WebLinuxBackend::new()),
        tier: Tier3,
        marker_file: None,
        started_vm_probe_order: None,
        list_all: true,
        balloon_support: false,
        warm_start_support: false,
        bundled_kernel: false,
        needs_plan_json: false,
        is_workload: true
    },
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
    /// legacy `mvmctl doctor` (balloon + warm-start matrices), `mvmctl ls`
    /// (list-all), and the started-VM probe. Freeze those orders so a table
    /// reshuffle can't silently change what users see or the probe priority.
    #[test]
    fn descriptor_surface_ordering_is_frozen() {
        assert_eq!(selectors(balloon_support_descriptors()), ["qemu"]);
        assert_eq!(
            selectors(warm_start_support_descriptors()),
            Vec::<&str>::new()
        );
        assert_eq!(
            selectors(list_all_descriptors()),
            [
                "firecracker",
                "libkrun",
                "qemu",
                "hvf",
                "wasm",
                "apple-container",
                "web-linux"
            ]
        );
        // Started-VM probe is sorted by probe order, not declaration order.
        assert_eq!(
            selectors(started_vm_probe_descriptors().into_iter()),
            ["qemu", "libkrun", "firecracker", "hvf"]
        );
    }
}
