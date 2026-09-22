//! Static source inventory beyond binary targets: subscriber-initialization
//! sites, SDK/dispatch scripts, launch edges and backend telemetry endpoints.
//!
//! Same posture as the binary inventory: navigation anchors and fail-closed
//! drift detection, never evidence that capture runs. A registered entry is a
//! classification; only a runtime witness can certify coverage.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use crate::check_telemetry_inventory::{NonRuntimeCategory, Role};
use crate::fs_walk::for_each_file;

const SOURCES: &str = "specs/telemetry/sources.toml";

/// Producer keys from the validated binary inventory, `package/name` form.
#[derive(Debug, Default)]
pub struct KnownProducers {
    /// Guest and builder-guest runtime gaps: each needs at least one launch edge.
    pub launchable: BTreeSet<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sources {
    version: u32,
    #[serde(default)]
    subscriber_init: Vec<SubscriberInit>,
    #[serde(default)]
    script_source: Vec<ScriptSource>,
    #[serde(default)]
    launch_edge: Vec<LaunchEdge>,
    #[serde(default)]
    backend_endpoint: Vec<BackendEndpoint>,
}

/// One Rust site that installs a subscriber or process-global diagnostic state.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SubscriberInit {
    file: PathBuf,
    anchor: String,
    scope: Scope,
    role: Role,
    owner: String,
    gap: String,
    required_witness: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Scope {
    Global,
    Scoped,
}

/// One non-Rust producer surface: SDK module or dispatch/wrapper script.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScriptSource {
    path: PathBuf,
    anchor: String,
    language: Language,
    capture: ScriptCapture,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Language {
    Python,
    Javascript,
    Typescript,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ScriptCapture {
    RuntimeGap {
        role: Role,
        owner: String,
        gap: String,
        required_witness: String,
    },
    NonRuntime {
        category: NonRuntimeCategory,
        reason: String,
    },
}

/// One launcher-to-producer edge with its activation policy.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchEdge {
    producer: String,
    launcher: PathBuf,
    anchor: String,
    activation: EdgeActivation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    condition: Option<String>,
}

/// Inventory-level activation; an unlaunched optional helper is not a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EdgeActivation {
    /// Started on every boot of its image tier.
    Always,
    /// Started only under a named, host-observable condition.
    Conditional,
    /// Executed per explicit request; never required to witness.
    OnDemand,
    /// Bind-mount substitution over a workload path.
    Mediated,
    /// Only reachable through a retired provisioning path.
    Legacy,
    /// Bootstrap-seed init laid down by the host, not an image member.
    Seed,
    /// Built but launched by no current image or launcher; wiring it in
    /// requires inventory review, so the edge anchors its declaration.
    Unwired,
}

/// One backend telemetry-endpoint provisioning anchor.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackendEndpoint {
    backend: Backend,
    file: PathBuf,
    anchor: String,
    note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Backend {
    Shared,
    Firecracker,
    Libkrun,
    Hvf,
    Qemu,
    AppleContainer,
    Wasm,
}

const REQUIRED_BACKENDS: [Backend; 7] = [
    Backend::Shared,
    Backend::Firecracker,
    Backend::Libkrun,
    Backend::Hvf,
    Backend::Qemu,
    Backend::AppleContainer,
    Backend::Wasm,
];

#[derive(Debug, Default)]
struct Summary {
    subscriber_inits: usize,
    script_sources: usize,
    launch_edges: usize,
    backend_endpoints: usize,
}

/// Directories whose Rust files never carry a production subscriber install.
const EXEMPT_RUST_DIRS: [&str; 4] = ["tests", "fuzz", "benches", "examples"];

/// A file's pre-`#[cfg(test)]` region installing global diagnostic state.
fn installs_diagnostics(text: &str) -> bool {
    let region = text.split("#[cfg(test)]").next().unwrap_or(text);
    if [
        "set_global_default",
        "log::set_logger",
        "env_logger::",
        "panic::set_hook",
    ]
    .iter()
    .any(|pattern| region.contains(pattern))
    {
        return true;
    }
    region.contains("tracing_subscriber")
        && (region.contains(".init()") || region.contains("::init()"))
}

/// This gate names the scan patterns literally, so it must not flag itself.
const SELF_PATH: &str = "xtask/src/check_telemetry_sources.rs";

/// Rust files that must be registered as subscriber-initialization sites.
fn scan_rust_init_sites(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut sites = BTreeSet::new();
    for dir in ["crates", "src", "xtask/src"] {
        for_each_file(&root.join(dir), Some("rs"), &mut |path, text| {
            let relative = path.strip_prefix(root).unwrap_or(path);
            let exempt = relative == Path::new(SELF_PATH)
                || relative.components().any(|component| {
                    matches!(component, Component::Normal(name)
                        if EXEMPT_RUST_DIRS.iter().any(|dir| name == *dir))
                });
            if !exempt && installs_diagnostics(text) {
                sites.insert(relative.to_path_buf());
            }
        })?;
    }
    Ok(sites)
}

/// Script files that must be registered: every dispatch wrapper, plus every
/// SDK module whose text writes to a diagnostic or output stream.
fn scan_script_sources(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut sources = BTreeSet::new();
    for dir in ["nix/wrappers/python", "nix/wrappers/node"] {
        for_each_file(&root.join(dir), None, &mut |path, _| {
            let relative = path.strip_prefix(root).unwrap_or(path);
            let name = relative
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if !name.starts_with("README") {
                sources.insert(relative.to_path_buf());
            }
        })?;
    }
    let sdk_trees = [
        (
            "crates/mvm-sdk/sdks/python/mvm",
            "py",
            &["sys.stderr", "warnings.warn", "print("][..],
        ),
        (
            "crates/mvm-sdk/sdks/typescript/src",
            "ts",
            &[
                "console.error",
                "console.warn",
                "console.log",
                "process.stderr",
            ][..],
        ),
    ];
    for (dir, ext, patterns) in sdk_trees {
        for_each_file(&root.join(dir), Some(ext), &mut |path, text| {
            if patterns.iter().any(|pattern| text.contains(pattern)) {
                let relative = path.strip_prefix(root).unwrap_or(path);
                sources.insert(relative.to_path_buf());
            }
        })?;
    }
    Ok(sources)
}

fn check_entry_path(root: &Path, path: &Path, anchor: &str) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty()
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "path must be workspace-relative without traversal"
    );
    ensure!(!anchor.trim().is_empty(), "anchor must not be empty");
    let text = std::fs::read_to_string(root.join(path))
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        text.contains(anchor),
        "anchor not found in {}",
        path.display()
    );
    Ok(())
}

fn nonempty(errors: &mut Vec<String>, label: &str, fields: &[(&str, &str)]) {
    for (field, value) in fields {
        if value.trim().is_empty() {
            errors.push(format!("{label}: {field} must not be empty"));
        }
    }
}

fn validate_subscriber_inits(
    root: &Path,
    entries: &[SubscriberInit],
    scanned: &BTreeSet<PathBuf>,
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for entry in entries {
        let label = format!("subscriber_init {}", entry.file.display());
        if !seen.insert(entry.file.clone()) {
            errors.push(format!("duplicate {label}"));
            continue;
        }
        if let Err(error) = check_entry_path(root, &entry.file, &entry.anchor) {
            errors.push(format!("{label}: {error:#}"));
        }
        nonempty(
            errors,
            &label,
            &[
                ("owner", &entry.owner),
                ("gap", &entry.gap),
                ("required_witness", &entry.required_witness),
            ],
        );
    }
    for site in scanned {
        if !seen.contains(site) {
            errors.push(format!(
                "unregistered subscriber initialization site {}",
                site.display()
            ));
        }
    }
}

fn validate_script_sources(
    root: &Path,
    entries: &[ScriptSource],
    scanned: &BTreeSet<PathBuf>,
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for entry in entries {
        let label = format!("script_source {}", entry.path.display());
        if !seen.insert(entry.path.clone()) {
            errors.push(format!("duplicate {label}"));
            continue;
        }
        if let Err(error) = check_entry_path(root, &entry.path, &entry.anchor) {
            errors.push(format!("{label}: {error:#}"));
        }
        match &entry.capture {
            ScriptCapture::RuntimeGap {
                owner,
                gap,
                required_witness,
                ..
            } => nonempty(
                errors,
                &label,
                &[
                    ("owner", owner),
                    ("gap", gap),
                    ("required_witness", required_witness),
                ],
            ),
            ScriptCapture::NonRuntime { reason, .. } => {
                nonempty(errors, &label, &[("reason", reason)]);
            }
        }
    }
    for source in scanned {
        if !seen.contains(source) {
            errors.push(format!("unregistered script source {}", source.display()));
        }
    }
}

fn validate_launch_edges(
    root: &Path,
    entries: &[LaunchEdge],
    producers: &KnownProducers,
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    let mut launched = BTreeSet::new();
    for entry in entries {
        let label = format!(
            "launch_edge {} via {}",
            entry.producer,
            entry.launcher.display()
        );
        if !seen.insert((
            entry.producer.clone(),
            entry.launcher.clone(),
            entry.anchor.clone(),
        )) {
            errors.push(format!("duplicate {label}"));
            continue;
        }
        if !producers.launchable.contains(&entry.producer) {
            errors.push(format!(
                "{label}: producer is not a guest/builder runtime gap in the binary inventory"
            ));
        }
        if let Err(error) = check_entry_path(root, &entry.launcher, &entry.anchor) {
            errors.push(format!("{label}: {error:#}"));
        }
        match (entry.activation, &entry.condition) {
            (EdgeActivation::Conditional, Some(condition)) if !condition.trim().is_empty() => {}
            (EdgeActivation::Conditional, _) => {
                errors.push(format!("{label}: conditional activation needs a condition"));
            }
            (_, Some(_)) => {
                errors.push(format!(
                    "{label}: only conditional activation takes a condition"
                ));
            }
            (_, None) => {}
        }
        launched.insert(entry.producer.clone());
    }
    for producer in &producers.launchable {
        if !launched.contains(producer) {
            errors.push(format!("guest producer {producer} has no launch edge"));
        }
    }
}

fn validate_backend_endpoints(root: &Path, entries: &[BackendEndpoint], errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    let mut covered: BTreeMap<Backend, usize> = BTreeMap::new();
    for entry in entries {
        let label = format!(
            "backend_endpoint {:?} {}",
            entry.backend,
            entry.file.display()
        );
        if !seen.insert((entry.backend, entry.file.clone(), entry.anchor.clone())) {
            errors.push(format!("duplicate {label}"));
            continue;
        }
        if let Err(error) = check_entry_path(root, &entry.file, &entry.anchor) {
            errors.push(format!("{label}: {error:#}"));
        }
        nonempty(errors, &label, &[("note", &entry.note)]);
        *covered.entry(entry.backend).or_default() += 1;
    }
    for backend in REQUIRED_BACKENDS {
        if !covered.contains_key(&backend) {
            errors.push(format!(
                "backend {backend:?} has no telemetry endpoint entry"
            ));
        }
    }
}

fn validate(
    root: &Path,
    sources: &Sources,
    producers: &KnownProducers,
    rust_sites: &BTreeSet<PathBuf>,
    script_files: &BTreeSet<PathBuf>,
) -> Result<Summary> {
    ensure!(
        sources.version == 1,
        "unsupported telemetry sources version {}",
        sources.version
    );
    ensure!(
        !sources.subscriber_init.is_empty()
            && !sources.launch_edge.is_empty()
            && !sources.backend_endpoint.is_empty(),
        "telemetry source inventory sections must not be empty"
    );
    let mut errors = Vec::new();
    validate_subscriber_inits(root, &sources.subscriber_init, rust_sites, &mut errors);
    validate_script_sources(root, &sources.script_source, script_files, &mut errors);
    validate_launch_edges(root, &sources.launch_edge, producers, &mut errors);
    validate_backend_endpoints(root, &sources.backend_endpoint, &mut errors);
    if !errors.is_empty() {
        bail!(
            "telemetry source inventory drift:\n  {}",
            errors.join("\n  ")
        );
    }
    Ok(Summary {
        subscriber_inits: sources.subscriber_init.len(),
        script_sources: sources.script_source.len(),
        launch_edges: sources.launch_edge.len(),
        backend_endpoints: sources.backend_endpoint.len(),
    })
}

/// Validate the source inventory; classification only, never runtime coverage.
pub fn run(workspace: &Path, producers: &KnownProducers) -> Result<()> {
    let text =
        std::fs::read_to_string(workspace.join(SOURCES)).context("read telemetry sources")?;
    let sources: Sources = toml::from_str(&text).context("parse telemetry sources")?;
    let rust_sites = scan_rust_init_sites(workspace)?;
    let script_files = scan_script_sources(workspace)?;
    let summary = validate(workspace, &sources, producers, &rust_sites, &script_files)?;
    eprintln!(
        "check-telemetry-inventory: {} subscriber init sites, {} script sources, {} launch edges, {} backend endpoints classified; runtime coverage is NOT certified",
        summary.subscriber_inits,
        summary.script_sources,
        summary.launch_edges,
        summary.backend_endpoints
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        root: tempfile::TempDir,
        sources: Sources,
        producers: KnownProducers,
    }

    fn write(root: &Path, path: &str, text: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "crates/app/src/main.rs",
            "fn main() { tracing_subscriber::fmt().init(); }\n",
        );
        write(root.path(), "crates/app/src/lib.rs", "pub fn quiet() {}\n");
        write(
            root.path(),
            "nix/wrappers/python/oneshot.py",
            "ENVELOPE_MARKER\nprint('x', file=sys.stderr)\n",
        );
        write(
            root.path(),
            "crates/mvm-sdk/sdks/python/mvm/_sandbox.py",
            "def go():\n    print('diag', file=sys.stderr)\n",
        );
        write(root.path(), "nix/lib/mk-guest.nix", "AGENT_FORK marker\n");
        write(
            root.path(),
            "crates/endpoints.rs",
            "TELEMETRY_PORT anchor\n",
        );
        let sources: Sources = toml::from_str(
            r#"
version = 1

[[subscriber_init]]
file = "crates/app/src/main.rs"
anchor = "tracing_subscriber::fmt().init()"
scope = "global"
role = "host"
owner = "app main"
gap = "Local fmt output only."
required_witness = "Host collector receives startup and diagnostics."

[[script_source]]
path = "nix/wrappers/python/oneshot.py"
anchor = "ENVELOPE_MARKER"
language = "python"
[script_source.capture]
kind = "runtime-gap"
role = "workload-guest"
owner = "runner dispatch"
gap = "Envelope on stderr only."
required_witness = "Collector receives dispatch diagnostics."

[[script_source]]
path = "crates/mvm-sdk/sdks/python/mvm/_sandbox.py"
anchor = "print('diag'"
language = "python"
[script_source.capture]
kind = "non-runtime"
category = "developer-tool"
reason = "Host-side driver output."

[[launch_edge]]
producer = "pkg/agent"
launcher = "nix/lib/mk-guest.nix"
anchor = "AGENT_FORK"
activation = "always"

[[launch_edge]]
producer = "pkg/helper"
launcher = "nix/lib/mk-guest.nix"
anchor = "AGENT_FORK"
activation = "conditional"
condition = "vsock egress opt-in"
"#,
        )
        .unwrap();
        let mut sources = sources;
        for backend in [
            "shared",
            "firecracker",
            "libkrun",
            "hvf",
            "qemu",
            "apple-container",
            "wasm",
        ] {
            let entry: BackendEndpoint = toml::from_str(&format!(
                r#"
backend = "{backend}"
file = "crates/endpoints.rs"
anchor = "TELEMETRY_PORT"
note = "standing endpoint"
"#
            ))
            .unwrap();
            sources.backend_endpoint.push(entry);
        }
        let producers = KnownProducers {
            launchable: BTreeSet::from(["pkg/agent".into(), "pkg/helper".into()]),
        };
        Fixture {
            root,
            sources,
            producers,
        }
    }

    fn check(fx: &Fixture) -> Result<Summary> {
        let rust_sites = scan_rust_init_sites(fx.root.path()).unwrap();
        let script_files = scan_script_sources(fx.root.path()).unwrap();
        validate(
            fx.root.path(),
            &fx.sources,
            &fx.producers,
            &rust_sites,
            &script_files,
        )
    }

    #[test]
    fn complete_inventory_passes_without_claiming_coverage() {
        let fx = fixture();
        let summary = check(&fx).unwrap();
        assert_eq!(summary.subscriber_inits, 1);
        assert_eq!(summary.script_sources, 2);
        assert_eq!(summary.launch_edges, 2);
        assert_eq!(summary.backend_endpoints, 7);
    }

    #[test]
    fn new_subscriber_install_site_fails_until_registered() {
        let fx = fixture();
        write(
            fx.root.path(),
            "crates/app/src/extra.rs",
            "pub fn hook() { let _ = tracing::subscriber::set_global_default(sub); }\n",
        );
        let error = check(&fx).unwrap_err().to_string();
        assert!(
            error.contains("unregistered subscriber initialization site"),
            "{error}"
        );
        assert!(error.contains("crates/app/src/extra.rs"), "{error}");
    }

    #[test]
    fn test_only_and_test_dir_subscribers_are_exempt() {
        let fx = fixture();
        write(
            fx.root.path(),
            "crates/app/src/scoped.rs",
            "pub fn x() {}\n#[cfg(test)]\nmod tests { fn t() { tracing_subscriber::fmt().init(); } }\n",
        );
        write(
            fx.root.path(),
            "crates/app/tests/integration.rs",
            "fn t() { tracing_subscriber::fmt().init(); }\n",
        );
        check(&fx).unwrap();
    }

    #[test]
    fn panic_hook_and_logger_installs_are_scanned() {
        for text in [
            "fn a() { std::panic::set_hook(Box::new(|_| {})); }\n",
            "fn a() { log::set_logger(&L).unwrap(); }\n",
            "fn a() { env_logger::init(); }\n",
        ] {
            let fx = fixture();
            write(fx.root.path(), "crates/app/src/extra.rs", text);
            let error = check(&fx).unwrap_err().to_string();
            assert!(error.contains("crates/app/src/extra.rs"), "{text}: {error}");
        }
    }

    #[test]
    fn new_wrapper_script_fails_until_registered() {
        let fx = fixture();
        write(fx.root.path(), "nix/wrappers/node/extra.mjs", "dispatch\n");
        let error = check(&fx).unwrap_err().to_string();
        assert!(error.contains("unregistered script source"), "{error}");
        assert!(error.contains("nix/wrappers/node/extra.mjs"), "{error}");
    }

    #[test]
    fn sdk_module_writing_output_fails_until_registered() {
        let fx = fixture();
        write(
            fx.root.path(),
            "crates/mvm-sdk/sdks/typescript/src/_extra.ts",
            "console.error('x');\n",
        );
        let error = check(&fx).unwrap_err().to_string();
        assert!(error.contains("_extra.ts"), "{error}");
    }

    #[test]
    fn silent_sdk_module_needs_no_entry() {
        let fx = fixture();
        write(
            fx.root.path(),
            "crates/mvm-sdk/sdks/typescript/src/_quiet.ts",
            "export const x = 1;\n",
        );
        check(&fx).unwrap();
    }

    #[test]
    fn guest_producer_without_launch_edge_fails() {
        let mut fx = fixture();
        fx.producers.launchable.insert("pkg/ghost".into());
        let error = check(&fx).unwrap_err().to_string();
        assert!(
            error.contains("guest producer pkg/ghost has no launch edge"),
            "{error}"
        );
    }

    #[test]
    fn launch_edge_for_unknown_producer_fails() {
        let mut fx = fixture();
        fx.producers.launchable.remove("pkg/helper");
        let error = check(&fx).unwrap_err().to_string();
        assert!(error.contains("not a guest/builder runtime gap"), "{error}");
    }

    #[test]
    fn conditional_edges_require_a_condition_and_others_refuse_one() {
        let mut fx = fixture();
        fx.sources.launch_edge[1].condition = None;
        let error = check(&fx).unwrap_err().to_string();
        assert!(error.contains("needs a condition"), "{error}");
        let mut fx = fixture();
        fx.sources.launch_edge[0].condition = Some("spurious".into());
        let error = check(&fx).unwrap_err().to_string();
        assert!(
            error.contains("only conditional activation takes a condition"),
            "{error}"
        );
    }

    #[test]
    fn missing_backend_coverage_fails_by_name() {
        let mut fx = fixture();
        fx.sources
            .backend_endpoint
            .retain(|entry| entry.backend != Backend::Wasm);
        let error = check(&fx).unwrap_err().to_string();
        assert!(
            error.contains("backend Wasm has no telemetry endpoint entry"),
            "{error}"
        );
    }

    #[test]
    fn anchor_drift_and_missing_files_fail() {
        let mut fx = fixture();
        fx.sources.subscriber_init[0].anchor = "renamed_anchor".into();
        let error = check(&fx).unwrap_err().to_string();
        assert!(error.contains("anchor not found"), "{error}");
        let mut fx = fixture();
        fx.sources.launch_edge[0].launcher = "nix/lib/gone.nix".into();
        assert!(check(&fx).is_err());
    }

    #[test]
    fn traversal_paths_are_rejected() {
        let mut fx = fixture();
        fx.sources.subscriber_init[0].file = "../outside.rs".into();
        let error = check(&fx).unwrap_err().to_string();
        assert!(error.contains("without traversal"), "{error}");
    }

    #[test]
    fn duplicates_and_empty_evidence_fail() {
        let mut fx = fixture();
        let duplicate: SubscriberInit =
            serde_json::from_value(serde_json::to_value(&fx.sources.subscriber_init[0]).unwrap())
                .unwrap();
        fx.sources.subscriber_init.push(duplicate);
        assert!(check(&fx).unwrap_err().to_string().contains("duplicate"));
        let mut fx = fixture();
        fx.sources.subscriber_init[0].gap = "  ".into();
        assert!(
            check(&fx)
                .unwrap_err()
                .to_string()
                .contains("gap must not be empty")
        );
    }

    #[test]
    fn unknown_fields_variants_and_versions_fail_closed() {
        let mut fx = fixture();
        let base = serde_json::to_value(&fx.sources).unwrap();
        let mut changed = base.clone();
        changed["surprise"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Sources>(changed).is_err());
        let mut changed = base.clone();
        changed["script_source"][0]["capture"]["kind"] = serde_json::json!("covered");
        assert!(serde_json::from_value::<Sources>(changed).is_err());
        let mut changed = base;
        changed["backend_endpoint"][0]["backend"] = serde_json::json!("docker");
        assert!(serde_json::from_value::<Sources>(changed).is_err());
        fx.sources.version = 2;
        assert!(
            check(&fx)
                .unwrap_err()
                .to_string()
                .contains("unsupported telemetry sources version")
        );
    }

    #[test]
    fn sources_roundtrip_preserves_classifications() {
        let fx = fixture();
        let encoded = toml::to_string(&fx.sources).unwrap();
        let decoded: Sources = toml::from_str(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&fx.sources).unwrap(),
            serde_json::to_value(&decoded).unwrap()
        );
    }

    #[test]
    fn real_workspace_sources_match() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let producers = crate::check_telemetry_inventory::known_producers(root).unwrap();
        run(root, &producers).unwrap();
    }
}
