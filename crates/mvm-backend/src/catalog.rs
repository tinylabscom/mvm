use crate::apple_container::AppleContainerBackend;
use crate::backend::{AnyBackend, BackendTier, FirecrackerBackend};
use crate::libkrun::LibkrunBackend;
use crate::mock::MockBackend;
use crate::qemu::QemuBackend;
use crate::vz::VzBackend;
use mvm_core::vm_backend::VmBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCatalogEntry {
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

impl BackendCatalogEntry {
    pub fn matches_selector(self, selector: &str) -> bool {
        self.selector == selector || self.aliases.contains(&selector)
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

        pub const BACKEND_CATALOG: &[BackendCatalogEntry] = &[
            $(
                BackendCatalogEntry {
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

        impl AnyBackend {
            pub(crate) fn kind(&self) -> BackendKind {
                match self {
                    $(Self::$kind(_) => BackendKind::$kind),*
                }
            }

            pub(crate) fn inner(&self) -> &dyn VmBackend {
                match self {
                    $(Self::$kind(backend) => backend),*
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
        kind: AppleContainer,
        selector: "apple-container",
        aliases: [],
        constructor: AnyBackend::AppleContainer(AppleContainerBackend),
        tier: Tier2,
        marker_file: None,
        started_vm_probe_order: None,
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
    }
];

pub fn entries() -> &'static [BackendCatalogEntry] {
    BACKEND_CATALOG
}

pub fn entry(kind: BackendKind) -> &'static BackendCatalogEntry {
    BACKEND_CATALOG
        .iter()
        .find(|entry| entry.kind == kind)
        .expect("backend kind must exist in catalog")
}

pub fn kind_for_selector(selector: &str) -> Option<BackendKind> {
    BACKEND_CATALOG
        .iter()
        .find(|entry| entry.matches_selector(selector))
        .map(|entry| entry.kind)
}

pub fn kind_for_marker_file(marker_file: &str) -> Option<BackendKind> {
    BACKEND_CATALOG
        .iter()
        .find(|entry| entry.marker_file == Some(marker_file))
        .map(|entry| entry.kind)
}

pub fn started_vm_probe_entries() -> Vec<&'static BackendCatalogEntry> {
    let mut entries: Vec<_> = BACKEND_CATALOG
        .iter()
        .filter(|entry| entry.started_vm_probe_order.is_some())
        .collect();
    entries.sort_by_key(|entry| {
        entry
            .started_vm_probe_order
            .expect("started-vm probe entries must have a probe order")
    });
    entries
}

pub fn list_all_entries() -> impl Iterator<Item = &'static BackendCatalogEntry> {
    BACKEND_CATALOG
        .iter()
        .filter(|entry| entry.include_in_list_all)
}

pub fn balloon_support_entries() -> impl Iterator<Item = &'static BackendCatalogEntry> {
    BACKEND_CATALOG
        .iter()
        .filter(|entry| entry.include_in_balloon_support)
}

pub fn warm_start_support_entries() -> impl Iterator<Item = &'static BackendCatalogEntry> {
    BACKEND_CATALOG
        .iter()
        .filter(|entry| entry.include_in_warm_start_support)
}
