//! The per-backend host-component table.
//!
//! One row per [`BackendKind`] declares which files the signed release
//! archive carries for that backend, the host window they apply to, and
//! whether install picks the backend automatically inside that window.
//! `install.sh` (through the generated `components.tsv` shipped in the
//! archive), `mvmctl backend list|add|remove|detect`, `mvmctl doctor` and
//! `xtask check-per-vm-host-binaries-sync` all read this table, so adding a
//! backend without a row — or a row without an implementation — fails a
//! test instead of drifting.
//!
//! A backend with no host components (firecracker, qemu, wasm, …) has an
//! empty `files` list: it is installable in the sense that there is nothing
//! to place. `selectable` marks the backends install can offer or accept
//! through `--backend`; opt-in special-purpose tiers stay out of that
//! surface.

use mvm_core::platform::{Platform, current};
use mvm_core::vm_backend::BackendKind;

/// One file a backend needs from the signed release archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentFile {
    /// Path inside the archive, relative to its `mvmctl-<target>/` root and
    /// identically relative to the staged release directory.
    pub path: &'static str,
    pub kind: ComponentKind,
}

/// What install does with a [`ComponentFile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentKind {
    /// An executable: staged into the release directory and linked from the
    /// install (PATH) directory beside `mvmctl`.
    Binary,
    /// A directory staged into the release directory, verbatim.
    Directory,
    /// A plain data file staged into the release directory.
    Data,
}

impl ComponentKind {
    /// The tag used in the generated `components.tsv`.
    const fn tsv_tag(self) -> &'static str {
        match self {
            Self::Binary => "bin",
            Self::Directory => "dir",
            Self::Data => "file",
        }
    }

    fn from_tsv_tag(tag: &str) -> Option<Self> {
        match tag {
            "bin" => Some(Self::Binary),
            "dir" => Some(Self::Directory),
            "file" => Some(Self::Data),
            _ => None,
        }
    }
}

/// The host window one backend row applies to. Every field is a fact about
/// the host the install runs on, so the matcher stays a pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostWindow {
    /// The release archive target triple, e.g. `aarch64-apple-darwin`.
    pub target: &'static str,
    /// First supported macOS major version (Darwin targets only).
    pub macos_min: Option<u32>,
    /// First unsupported macOS major version (exclusive upper bound).
    pub macos_max_exclusive: Option<u32>,
    /// Requires `/dev/kvm` (Linux targets only).
    pub needs_kvm: bool,
    /// Install picks this backend automatically for a host in this window.
    pub install_default: bool,
    /// Install offers this backend in this window (picker / `--backend`).
    pub selectable: bool,
}

/// The host facts a window match needs, injected so the logic is unit-testable
/// without spoofing the live OS version or compile-time target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFacts {
    /// The release target triple of this build (the archive it came from).
    pub target: &'static str,
    /// The running macOS major version; `None` off macOS.
    pub macos_major: Option<u32>,
    /// Whether `/dev/kvm` is usable.
    pub has_kvm: bool,
}

impl HostWindow {
    /// Whether a host with these facts falls inside the window.
    pub fn contains(&self, host: &HostFacts) -> bool {
        if self.target != host.target {
            return false;
        }
        if let Some(min) = self.macos_min
            && host.macos_major.is_none_or(|major| major < min)
        {
            return false;
        }
        if let Some(max) = self.macos_max_exclusive
            && host.macos_major.is_some_and(|major| major >= max)
        {
            return false;
        }
        !(self.needs_kvm && !host.has_kvm)
    }

    /// The window as a short human phrase, for `backend list` and refusals.
    pub fn describe(&self) -> String {
        let mut out = match self.target {
            "aarch64-apple-darwin" => "macOS Apple Silicon".to_string(),
            "x86_64-unknown-linux-gnu" => "Linux x86_64".to_string(),
            "aarch64-unknown-linux-gnu" => "Linux aarch64".to_string(),
            other => other.to_string(),
        };
        match (self.macos_min, self.macos_max_exclusive) {
            (Some(min), Some(max)) => out.push_str(&format!(" {min}–{}", max - 1)),
            (Some(min), None) => out.push_str(&format!(" {min}+")),
            (None, Some(max)) => out.push_str(&format!(" up to macOS {}", max - 1)),
            (None, None) => {}
        }
        if self.needs_kvm {
            out.push_str(" with /dev/kvm");
        }
        out
    }
}

/// One backend's host-component set: the row install, the `backend` verbs,
/// doctor and the sync gate all read.
#[derive(Debug, Clone, Copy)]
pub struct BackendComponentSet {
    /// The same `BackendKind` the `VmBackend`/`VmmDriver` implementations
    /// report — never a parallel string.
    pub backend: BackendKind,
    /// Host windows this backend supports. Empty when the backend never runs
    /// on a native host (browser tier, test-only mock).
    pub hosts: &'static [HostWindow],
    /// The archive paths this backend needs; empty when it has none.
    pub files: &'static [ComponentFile],
    /// One-line capability summary for `backend list`.
    pub summary: &'static str,
    /// Why the backend is off the native-host surface, when `hosts` is empty.
    pub unavailable: &'static str,
}

const FIRECRACKER_HOSTS: &[HostWindow] = &[
    HostWindow {
        target: "x86_64-unknown-linux-gnu",
        macos_min: None,
        macos_max_exclusive: None,
        needs_kvm: true,
        install_default: true,
        selectable: true,
    },
    HostWindow {
        target: "aarch64-unknown-linux-gnu",
        macos_min: None,
        macos_max_exclusive: None,
        needs_kvm: true,
        install_default: true,
        selectable: true,
    },
];

const QEMU_HOSTS: &[HostWindow] = &[
    HostWindow {
        target: "x86_64-unknown-linux-gnu",
        macos_min: None,
        macos_max_exclusive: None,
        needs_kvm: false,
        install_default: false,
        selectable: true,
    },
    HostWindow {
        target: "aarch64-unknown-linux-gnu",
        macos_min: None,
        macos_max_exclusive: None,
        needs_kvm: false,
        install_default: false,
        selectable: true,
    },
];

const HVF_HOSTS: &[HostWindow] = &[HostWindow {
    target: "aarch64-apple-darwin",
    macos_min: Some(26),
    macos_max_exclusive: None,
    needs_kvm: false,
    install_default: true,
    selectable: true,
}];

const LIBKRUN_HOSTS: &[HostWindow] = &[HostWindow {
    target: "aarch64-apple-darwin",
    macos_min: Some(13),
    macos_max_exclusive: Some(26),
    needs_kvm: false,
    install_default: true,
    selectable: true,
}];

const WASM_HOSTS: &[HostWindow] = &[
    HostWindow {
        target: "x86_64-unknown-linux-gnu",
        macos_min: None,
        macos_max_exclusive: None,
        needs_kvm: false,
        install_default: false,
        selectable: false,
    },
    HostWindow {
        target: "aarch64-unknown-linux-gnu",
        macos_min: None,
        macos_max_exclusive: None,
        needs_kvm: false,
        install_default: false,
        selectable: false,
    },
    HostWindow {
        target: "aarch64-apple-darwin",
        macos_min: None,
        macos_max_exclusive: None,
        needs_kvm: false,
        install_default: false,
        selectable: false,
    },
];

const APPLE_CONTAINER_HOSTS: &[HostWindow] = &[HostWindow {
    target: "aarch64-apple-darwin",
    macos_min: Some(26),
    macos_max_exclusive: None,
    needs_kvm: false,
    install_default: false,
    selectable: false,
}];

const LIBKRUN_FILES: &[ComponentFile] = &[
    ComponentFile {
        path: "mvm-libkrun-supervisor",
        kind: ComponentKind::Binary,
    },
    ComponentFile {
        path: "lib",
        kind: ComponentKind::Directory,
    },
    ComponentFile {
        path: "licenses",
        kind: ComponentKind::Directory,
    },
    ComponentFile {
        path: "sources",
        kind: ComponentKind::Directory,
    },
    ComponentFile {
        path: "SOURCE-OFFER.txt",
        kind: ComponentKind::Data,
    },
    ComponentFile {
        path: "SOURCE-PINS",
        kind: ComponentKind::Data,
    },
];

const HVF_FILES: &[ComponentFile] = &[ComponentFile {
    path: "mvm-hvf-supervisor",
    kind: ComponentKind::Binary,
}];

/// The canonical per-backend component table: one row per `BackendKind`.
///
/// `every_backend_kind_has_exactly_one_row` holds the row set equal to
/// [`BackendKind::ALL`], so a backend added to the enum without a row fails
/// the build's tests; a row naming a kind with no `VmBackend` fails the
/// catalog's descriptor coverage the same way.
pub const BACKEND_COMPONENT_TABLE: &[BackendComponentSet] = &[
    BackendComponentSet {
        backend: BackendKind::Firecracker,
        hosts: FIRECRACKER_HOSTS,
        files: &[],
        summary: "KVM microVMs with jailer + seccomp; the production Linux tier",
        unavailable: "",
    },
    BackendComponentSet {
        backend: BackendKind::Libkrun,
        hosts: LIBKRUN_HOSTS,
        files: LIBKRUN_FILES,
        summary: "libkrun + libkrunfw (bundled kernel) for macOS 13–25 Apple Silicon",
        unavailable: "",
    },
    BackendComponentSet {
        backend: BackendKind::Qemu,
        hosts: QEMU_HOSTS,
        files: &[],
        summary: "Software-emulated dev/test tier for Linux hosts without KVM",
        unavailable: "",
    },
    BackendComponentSet {
        backend: BackendKind::Mock,
        hosts: &[],
        files: &[],
        summary: "In-memory test double",
        unavailable: "test-only; never shipped",
    },
    BackendComponentSet {
        backend: BackendKind::Hvf,
        hosts: HVF_HOSTS,
        files: HVF_FILES,
        summary: "Hypervisor.framework VMM; the macOS 26+ Apple Silicon tier",
        unavailable: "",
    },
    BackendComponentSet {
        backend: BackendKind::Wasm,
        hosts: WASM_HOSTS,
        files: &[],
        summary: "Host wasmtime running a WASI module; opt-in portability tier",
        unavailable: "",
    },
    BackendComponentSet {
        backend: BackendKind::WebLinux,
        hosts: &[],
        files: &[],
        summary: "Browser-hosted Linux under QEMU-Wasm",
        unavailable: "runs in a browser, not on a native host",
    },
    BackendComponentSet {
        backend: BackendKind::AppleContainer,
        hosts: APPLE_CONTAINER_HOSTS,
        files: &[],
        summary: "Apple's container kernel on the HVF VMM; shares the hvf supervisor",
        unavailable: "",
    },
];

/// Every row in the table.
pub fn component_table() -> &'static [BackendComponentSet] {
    BACKEND_COMPONENT_TABLE
}

/// The row for one backend.
pub fn row_for(kind: BackendKind) -> &'static BackendComponentSet {
    BACKEND_COMPONENT_TABLE
        .iter()
        .find(|row| row.backend == kind)
        .expect("every BackendKind has a component-table row")
}

/// The row named `name` (the backend's stable label), if any.
pub fn row_for_name(name: &str) -> Option<&'static BackendComponentSet> {
    BackendKind::from_label(name).map(row_for)
}

/// The rows install may offer on this host: selectable, and at least one
/// host window contains it.
pub fn viable_for(host: &HostFacts) -> Vec<&'static BackendComponentSet> {
    BACKEND_COMPONENT_TABLE
        .iter()
        .filter(|row| {
            row.hosts
                .iter()
                .any(|window| window.selectable && window.contains(host))
        })
        .collect()
}

/// The install-time default backend for this host: the default-marked viable
/// row, or the only viable row when none is marked (a host with exactly one
/// viable backend has nothing to choose). `None` when no backend is viable —
/// the install then fails with the supported matrix rather than staging a
/// partial install.
///
/// This is deliberately not the runtime auto-detect: the runtime ladder
/// answers hvf on every Apple Silicon macOS tier and never selects libkrun,
/// while the install answer must be libkrun on macOS 13–25, where hvf is
/// outside its support window. The two are different functions.
pub fn detect_install_default_for(host: &HostFacts) -> Option<BackendKind> {
    let viable = viable_for(host);
    let mut default = None;
    for row in &viable {
        if row
            .hosts
            .iter()
            .any(|window| window.selectable && window.install_default && window.contains(host))
        {
            default = Some(row.backend);
        }
    }
    default.or(match viable.as_slice() {
        [only] => Some(only.backend),
        _ => None,
    })
}

/// Why `row` is not usable on `host`, phrased from the row's windows.
/// `None` means the host is inside some window (viable, though not
/// necessarily selectable).
pub fn not_available_reason(row: &'static BackendComponentSet, host: &HostFacts) -> Option<String> {
    if row.hosts.iter().any(|window| window.contains(host)) {
        return None;
    }
    if row.hosts.is_empty() {
        return Some(row.unavailable.to_string());
    }
    let needs = row
        .hosts
        .iter()
        .map(HostWindow::describe)
        .collect::<Vec<_>>()
        .join(" or ");
    Some(format!("requires {needs}"))
}

/// The release target triple of this build — the archive this `mvmctl` came
/// from, which is also the host's own triple for every published archive.
pub fn host_release_target() -> Option<&'static str> {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return Some("aarch64-apple-darwin");
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return Some("x86_64-apple-darwin");
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    return Some("x86_64-unknown-linux-gnu");
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    return Some("aarch64-unknown-linux-gnu");
    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "linux"),
    )))]
    return None;
}

/// The live host facts: this build's target triple, the running macOS
/// version, and the `/dev/kvm` probe.
pub fn live_host() -> Option<HostFacts> {
    let platform = current();
    Some(HostFacts {
        target: host_release_target()?,
        macos_major: live_macos_major(platform),
        has_kvm: platform.has_kvm(),
    })
}

/// The directories a staged component can sit in relative to this running
/// `mvmctl`: beside the executable as invoked (macOS reports the install-dir
/// link) and beside the fully resolved executable (Linux reports the release
/// directory).
pub fn component_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.to_path_buf());
        }
        if let Ok(resolved) = exe.canonicalize()
            && let Some(dir) = resolved.parent()
            && !dirs.contains(&dir.to_path_buf())
        {
            dirs.push(dir.to_path_buf());
        }
    }
    dirs
}

/// Whether every file `row` lists is present in one of `dirs`. A row with no
/// files has nothing staged and is never "present" in this sense.
pub fn component_files_present(row: &BackendComponentSet, dirs: &[std::path::PathBuf]) -> bool {
    !row.files.is_empty()
        && row
            .files
            .iter()
            .all(|file| dirs.iter().any(|dir| dir.join(file.path).exists()))
}

/// The running macOS major version. The platform predicates answer the two
/// release-relevant boundaries (13 and 26), which is all a window match can
/// ask; compose them into the major rather than probe `sw_vers` a second way.
fn live_macos_major(platform: Platform) -> Option<u32> {
    if !matches!(platform, Platform::MacOS) {
        return None;
    }
    if platform.is_hvf_default_tier() {
        // The 26 boundary is the highest the table distinguishes today.
        return Some(26);
    }
    if platform.has_macos13_or_later() {
        return Some(13);
    }
    Some(0)
}

// ──────────────────────────────────────────────────────────────────
// `components.tsv` — the table rendered for `install.sh`
// ──────────────────────────────────────────────────────────────────
//
// One row per (backend, host window); backends with no host windows render
// one row with `-` fields so the file enumerates every backend. Columns:
//
//   backend  target  macos_min  macos_max_exclusive  needs_kvm
//   install_default  selectable  files
//
// `-` marks an empty field. `files` is a space-separated `kind:path` list,
// `kind` one of `bin`, `dir`, `file`. `install.sh` matches rows against the
// host it runs on; it never duplicates the table's data.

/// Render the table as the `components.tsv` text shipped in the archive.
pub fn render_components_tsv() -> String {
    let mut out = String::from(
        "# mvm backend component table — generated from BACKEND_COMPONENT_TABLE; do not edit\n",
    );
    for row in BACKEND_COMPONENT_TABLE {
        let files = row
            .files
            .iter()
            .map(|file| format!("{}:{}", file.kind.tsv_tag(), file.path))
            .collect::<Vec<_>>()
            .join(" ");
        let windows: &[HostWindow] = if row.hosts.is_empty() {
            &[HostWindow {
                target: "-",
                macos_min: None,
                macos_max_exclusive: None,
                needs_kvm: false,
                install_default: false,
                selectable: false,
            }]
        } else {
            row.hosts
        };
        for window in windows {
            let files_cell = if window.target == "-" { "-" } else { &files };
            let files_cell = if files_cell.is_empty() {
                "-"
            } else {
                files_cell
            };
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                row.backend.as_str(),
                window.target,
                window.macos_min.map_or("-".to_string(), |v| v.to_string()),
                window
                    .macos_max_exclusive
                    .map_or("-".to_string(), |v| v.to_string()),
                if window.needs_kvm { "yes" } else { "no" },
                if window.install_default { "yes" } else { "no" },
                if window.selectable { "yes" } else { "no" },
                files_cell,
            ));
        }
    }
    out
}

/// A parsed `components.tsv` row — the shape install.sh consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentsTsvRow {
    pub backend: String,
    pub target: String,
    pub macos_min: Option<u32>,
    pub macos_max_exclusive: Option<u32>,
    pub needs_kvm: bool,
    pub install_default: bool,
    pub selectable: bool,
    pub files: Vec<ComponentFileOwned>,
}

/// A `kind:path` pair parsed from the files column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentFileOwned {
    pub kind: ComponentKind,
    pub path: String,
}

/// Parse the `components.tsv` text. Errors name the offending line.
pub fn parse_components_tsv(text: &str) -> anyhow::Result<Vec<ComponentsTsvRow>> {
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        anyhow::ensure!(
            fields.len() == 8,
            "components.tsv line {}: want 8 tab-separated fields, got {}",
            index + 1,
            fields.len()
        );
        let number = |field: &str| -> anyhow::Result<Option<u32>> {
            match field {
                "-" => Ok(None),
                other => other.parse::<u32>().map(Some).map_err(|e| {
                    anyhow::anyhow!("components.tsv line {}: {other:?}: {e}", index + 1)
                }),
            }
        };
        let flag = |field: &str| -> anyhow::Result<bool> {
            match field {
                "yes" => Ok(true),
                "no" => Ok(false),
                other => anyhow::bail!(
                    "components.tsv line {}: want yes/no, got {other:?}",
                    index + 1
                ),
            }
        };
        let mut files = Vec::new();
        if fields[7] != "-" {
            for entry in fields[7].split(' ') {
                let (kind, path) = entry.split_once(':').ok_or_else(|| {
                    anyhow::anyhow!(
                        "components.tsv line {}: file entry {entry:?} is not kind:path",
                        index + 1
                    )
                })?;
                let kind = ComponentKind::from_tsv_tag(kind).ok_or_else(|| {
                    anyhow::anyhow!(
                        "components.tsv line {}: unknown file kind {kind:?}",
                        index + 1
                    )
                })?;
                files.push(ComponentFileOwned {
                    kind,
                    path: path.to_string(),
                });
            }
        }
        rows.push(ComponentsTsvRow {
            backend: fields[0].to_string(),
            target: fields[1].to_string(),
            macos_min: number(fields[2])?,
            macos_max_exclusive: number(fields[3])?,
            needs_kvm: flag(fields[4])?,
            install_default: flag(fields[5])?,
            selectable: flag(fields[6])?,
            files,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(target: &'static str, macos_major: Option<u32>, has_kvm: bool) -> HostFacts {
        HostFacts {
            target,
            macos_major,
            has_kvm,
        }
    }

    /// The table covers the whole `BackendKind` enum exactly once — the
    /// tripwire that makes "adding a backend cannot leave one out" true.
    /// The row's kind then has to name a real `VmBackend`, which the
    /// catalog's descriptor coverage asserts on the mvm-runtime side.
    #[test]
    fn every_backend_kind_has_exactly_one_row() {
        assert_eq!(
            BACKEND_COMPONENT_TABLE.len(),
            BackendKind::ALL.len(),
            "BACKEND_COMPONENT_TABLE and BackendKind::ALL disagree"
        );
        for kind in BackendKind::ALL {
            let matches = BACKEND_COMPONENT_TABLE
                .iter()
                .filter(|row| row.backend == *kind)
                .count();
            assert_eq!(matches, 1, "{kind:?} must have exactly one table row");
        }
    }

    #[test]
    fn the_generated_tsv_round_trips_the_table() {
        let rows = parse_components_tsv(&render_components_tsv())
            .expect("the generated components.tsv parses");
        let mut expected = Vec::new();
        for row in BACKEND_COMPONENT_TABLE {
            if row.hosts.is_empty() {
                expected.push((row.backend, "-".to_string(), 0usize));
                continue;
            }
            for window in row.hosts {
                expected.push((row.backend, window.target.to_string(), row.files.len()));
            }
        }
        let got: Vec<(BackendKind, String, usize)> = rows
            .iter()
            .map(|row| {
                (
                    BackendKind::from_label(&row.backend).expect("a known backend label"),
                    row.target.clone(),
                    row.files.len(),
                )
            })
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn the_tsv_carries_the_libkrun_component_set() {
        let text = render_components_tsv();
        let line = text
            .lines()
            .find(|line| line.starts_with("libkrun\t"))
            .expect("a libkrun row");
        for path in [
            "bin:mvm-libkrun-supervisor",
            "dir:lib",
            "dir:licenses",
            "dir:sources",
            "file:SOURCE-OFFER.txt",
            "file:SOURCE-PINS",
        ] {
            assert!(line.contains(path), "the libkrun row must name {path}");
        }
        assert!(line.contains("\t13\t26\t"), "the libkrun window is 13–25");
    }

    #[test]
    fn parsing_refuses_a_malformed_row() {
        assert!(parse_components_tsv("hvf\taarch64-apple-darwin\n").is_err());
        assert!(
            parse_components_tsv("hvf\taarch64-apple-darwin\t26\t-\tno\tyes\tyes\twat:x\n")
                .is_err()
        );
        assert!(parse_components_tsv("# comment only\n").unwrap().is_empty());
    }

    #[test]
    fn install_detection_matches_the_support_matrix() {
        // macOS Apple Silicon: libkrun on 13–25, hvf on 26+, none below 13.
        let macos = |major| facts("aarch64-apple-darwin", Some(major), false);
        assert_eq!(
            detect_install_default_for(&macos(13)),
            Some(BackendKind::Libkrun)
        );
        assert_eq!(
            detect_install_default_for(&macos(15)),
            Some(BackendKind::Libkrun)
        );
        assert_eq!(
            detect_install_default_for(&macos(25)),
            Some(BackendKind::Libkrun)
        );
        assert_eq!(
            detect_install_default_for(&macos(26)),
            Some(BackendKind::Hvf)
        );
        assert_eq!(
            detect_install_default_for(&macos(27)),
            Some(BackendKind::Hvf)
        );
        assert_eq!(detect_install_default_for(&macos(12)), None);

        // Linux: firecracker with KVM, qemu without.
        let linux = |kvm: bool| facts("x86_64-unknown-linux-gnu", None, kvm);
        assert_eq!(
            detect_install_default_for(&linux(true)),
            Some(BackendKind::Firecracker)
        );
        assert_eq!(
            detect_install_default_for(&linux(false)),
            Some(BackendKind::Qemu)
        );

        // Intel macOS publishes no archive, so no host facts ever name it;
        // guard the window matcher anyway.
        assert_eq!(
            detect_install_default_for(&facts("x86_64-apple-darwin", Some(15), false)),
            None
        );
    }

    #[test]
    fn the_picker_set_is_the_selectable_viable_rows() {
        let names = |host: &HostFacts| {
            viable_for(host)
                .iter()
                .map(|row| row.backend.as_str())
                .collect::<Vec<_>>()
        };
        // Two viable backends on Linux-with-KVM: firecracker (auto) and qemu.
        assert_eq!(
            names(&facts("x86_64-unknown-linux-gnu", None, true)),
            ["firecracker", "qemu"]
        );
        // One viable backend on each macOS tier: no picker question exists.
        assert_eq!(
            names(&facts("aarch64-apple-darwin", Some(15), false)),
            ["libkrun"]
        );
        assert_eq!(
            names(&facts("aarch64-apple-darwin", Some(26), false)),
            ["hvf"]
        );
        // Opt-in tiers never join the picker.
        assert!(
            !names(&facts("aarch64-apple-darwin", Some(26), false)).contains(&"apple-container")
        );
    }

    #[test]
    fn unavailable_reasons_name_the_window() {
        let host = facts("aarch64-apple-darwin", Some(26), false);
        let libkrun = row_for(BackendKind::Libkrun);
        assert_eq!(
            not_available_reason(libkrun, &host).as_deref(),
            Some("requires macOS Apple Silicon 13–25")
        );
        assert_eq!(not_available_reason(row_for(BackendKind::Hvf), &host), None);
        let linux = facts("x86_64-unknown-linux-gnu", None, true);
        assert_eq!(
            not_available_reason(row_for(BackendKind::Hvf), &linux).as_deref(),
            Some("requires macOS Apple Silicon 26+")
        );
        assert_eq!(
            not_available_reason(row_for(BackendKind::WebLinux), &linux).as_deref(),
            Some("runs in a browser, not on a native host")
        );
        assert_eq!(
            not_available_reason(
                row_for(BackendKind::Firecracker),
                &facts("x86_64-unknown-linux-gnu", None, false)
            )
            .as_deref(),
            Some("requires Linux x86_64 with /dev/kvm or Linux aarch64 with /dev/kvm")
        );
    }

    #[test]
    fn window_matching_is_exact() {
        let window = HostWindow {
            target: "aarch64-apple-darwin",
            macos_min: Some(13),
            macos_max_exclusive: Some(26),
            needs_kvm: false,
            install_default: true,
            selectable: true,
        };
        assert!(window.contains(&facts("aarch64-apple-darwin", Some(13), false)));
        assert!(!window.contains(&facts("aarch64-apple-darwin", Some(26), false)));
        assert!(!window.contains(&facts("aarch64-apple-darwin", Some(12), false)));
        assert!(!window.contains(&facts("x86_64-unknown-linux-gnu", None, true)));
        // A Darwin window never matches a host that reports no macOS version.
        assert!(!window.contains(&facts("aarch64-apple-darwin", None, false)));

        let kvm = FIRECRACKER_HOSTS[0];
        assert!(!kvm.contains(&facts("x86_64-unknown-linux-gnu", None, false)));
        assert!(kvm.contains(&facts("x86_64-unknown-linux-gnu", None, true)));
    }

    #[test]
    fn live_host_matches_this_builds_target() {
        let host = live_host().expect("a supported build target");
        assert_eq!(host.target, host_release_target().unwrap());
    }

    /// Presence is all-or-nothing per row: a half-staged component set must
    /// not read as installed.
    #[test]
    fn presence_requires_every_listed_file() {
        let row = row_for(BackendKind::Libkrun);
        let dir = tempfile::tempdir().unwrap();
        assert!(!component_files_present(row, &[dir.path().to_path_buf()]));
        for file in row.files {
            let path = dir.path().join(file.path);
            if file.kind == ComponentKind::Directory {
                std::fs::create_dir_all(&path).unwrap();
            } else {
                std::fs::write(&path, b"x").unwrap();
            }
        }
        assert!(component_files_present(row, &[dir.path().to_path_buf()]));
        // A file-less row is never "present": there is nothing to stage.
        assert!(!component_files_present(row_for(BackendKind::Qemu), &[]));
    }

    #[test]
    fn component_binaries_are_per_vm_host_binaries() {
        // A Binary-kind component is spawned per-VM from beside mvmctl, so it
        // must also be in the per-VM host binary registry the release build
        // and package lists sync against.
        for row in BACKEND_COMPONENT_TABLE {
            for file in row.files {
                if file.kind != ComponentKind::Binary {
                    continue;
                }
                assert!(
                    crate::host_binaries::manifest::PER_VM_HOST_BINARIES
                        .iter()
                        .any(|binary| binary.name == file.path),
                    "{} is a backend component binary missing from PER_VM_HOST_BINARIES",
                    file.path
                );
            }
        }
    }
}
