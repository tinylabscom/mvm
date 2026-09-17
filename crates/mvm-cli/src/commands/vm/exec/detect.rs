//! Which source a run boots from, and what that choice implies.
//!
//! Split out of `exec.rs` because settling a boot source is a self-contained
//! decision: it reads the flags, the working directory and the runtime
//! catalog, and hands back one answer. Everything downstream — admission,
//! launch, teardown — consumes that answer without needing to know how it was
//! reached.

use super::RunArgs;
use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;

/// Whether a verb infers a boot source it was not given.
///
/// `run` is the one-shot where "just run this" is the whole point, so it infers.
/// `machine run` creates a named — possibly persistent — machine, and guessing
/// its base image from whatever directory you happened to be standing in is a
/// footgun there: `machine run` inside any Rust checkout would silently build a
/// machine on `rust:1-alpine`. It keeps its own error, which names every way to
/// supply a source. `--runtime` still works on both, because that is the user
/// naming one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum Inference {
    /// Infer from `mvm.toml`, then argv[0], then a project file.
    Enabled,
    /// Only an explicit `--runtime` resolves.
    ExplicitOnly,
}

/// Where a run's boot source came from once every rule has had its say.
///
/// Returned rather than logged from inside the resolver so the caller decides
/// how to say it: a boot the user did not explicitly ask for must not be silent
/// about why it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum ResolvedSource {
    /// The user named a source; nothing was inferred.
    Explicit,
    /// An `mvm.toml` in or above the working directory supplied it.
    ProjectManifest(PathBuf),
    /// The command or the working directory selected a catalog runtime.
    Runtime(mvm_core::runtime_catalog::Detection),
    /// Nothing matched; the bundled default image is used.
    BundledDefault,
}

impl ResolvedSource {
    /// Say what was inferred, on stderr.
    ///
    /// Not `ui::info`, which is opt-in chatter shown only under `--verbose`: a
    /// boot whose image the user did not choose has to announce itself every
    /// time, or the first they learn of it is a "command not found" from a
    /// guest they never picked. stderr keeps `--json` stdout machine-readable.
    pub(in crate::commands) fn announce(&self) {
        if let Some(note) = self.note() {
            eprintln!("[mvm] {note}");
        }
    }

    /// The line to print before booting, or `None` when the user already knows
    /// what they asked for.
    pub(in crate::commands) fn note(&self) -> Option<String> {
        match self {
            ResolvedSource::Explicit | ResolvedSource::BundledDefault => None,
            ResolvedSource::ProjectManifest(path) => Some(format!(
                "using {} from the project directory",
                path.display()
            )),
            ResolvedSource::Runtime(d) => Some(format!(
                "detected {} from {} — booting {}",
                d.runtime,
                d.via.describe(),
                d.image
            )),
        }
    }
}

/// Settle which source a run boots from, filling `args` in place.
///
/// One resolver for both verbs. The order is the whole contract:
///
/// 1. An explicit `--image` / `--manifest` / `--flake` / `--deployment` /
///    `--runtime-pack` wins and nothing is inferred.
/// 2. `--runtime <name>` resolves against the built-in catalog. An unknown name
///    refuses — it never falls through to a default.
/// 3. `--no-detect`, or a verb that only takes explicit sources, stops here.
/// 4. An `mvm.toml` in or above the working directory, found by the same
///    walk-up `mvmctl build` already uses.
/// 5. The command being run, then a project file in the working directory.
/// 6. The bundled default image.
///
/// Inference only ever picks a *source*. It does not touch policy: a detected
/// run admits through the same signed `ExecutionPlan` with the same default-deny
/// egress as one that named its image, which is what
/// `a_detected_run_is_still_deny_all_and_admitted` pins.
pub(in crate::commands) fn resolve_run_source(
    args: &mut RunArgs,
    cwd: &std::path::Path,
    inference: Inference,
) -> Result<ResolvedSource> {
    refuse_known_flag_after_double_dash(&args.argv)?;

    if args.image.is_some()
        || args.manifest.is_some()
        || args.flake.is_some()
        || args.deployment.is_some()
        || args.runtime_pack
    {
        return Ok(ResolvedSource::Explicit);
    }

    let catalog = mvm_core::runtime_catalog::RuntimeCatalog::builtin();

    if let Some(name) = args.runtime.clone() {
        let detection = catalog
            .resolve_named(&name)
            .map_err(|e| anyhow::anyhow!(e))?;
        args.image = Some(detection.image.clone());
        adopt_declared_bindings(args, &detection);
        return Ok(ResolvedSource::Runtime(detection));
    }

    if args.no_detect || inference == Inference::ExplicitOnly {
        refuse_if_argv_looks_like_an_image_reference(&args.argv)?;
        return Ok(ResolvedSource::BundledDefault);
    }

    if let Some(manifest) = mvm_core::domain::manifest::discover_manifest_from_dir(cwd)
        .context("looking for an mvm.toml in the working directory")?
    {
        args.manifest = Some(manifest.display().to_string());
        return Ok(ResolvedSource::ProjectManifest(manifest));
    }

    let present = project_files_in(cwd);
    if let Some(detection) = catalog
        .detect(args.argv.first().map(String::as_str), &present)
        .map_err(|e| anyhow::anyhow!(e))?
    {
        args.image = Some(detection.image.clone());
        adopt_declared_bindings(args, &detection);
        return Ok(ResolvedSource::Runtime(detection));
    }

    refuse_if_argv_looks_like_an_image_reference(&args.argv)?;
    Ok(ResolvedSource::BundledDefault)
}

/// The `--long` flags `RunArgs` declares, read from clap's own definition
/// rather than a hand-written list so a renamed or added flag is picked up
/// automatically instead of drifting out of sync.
fn run_flag_long_names() -> Vec<String> {
    <RunArgs as ClapArgs>::augment_args(clap::Command::new("run"))
        .get_arguments()
        .filter_map(|arg| arg.get_long())
        .map(|long| format!("--{long}"))
        .collect()
}

/// A known run flag placed after `--` lands in the guest argv instead of
/// configuring the run — silently wrong rather than refused, because
/// `trailing_var_arg` never reinterprets anything past that point as an
/// option. Only the token immediately after `--` is checked: a workload's
/// own program may legitimately take a same-named flag deeper in its own
/// argv (forwarding `--help` to itself, for instance), and only position 0
/// is unambiguous about what the user just typed.
fn refuse_known_flag_after_double_dash(argv: &[String]) -> Result<()> {
    let Some(first) = argv.first() else {
        return Ok(());
    };
    if run_flag_long_names().iter().any(|flag| flag == first) {
        anyhow::bail!(
            "`{first}` is a run flag, but it appears right after `--`, so it was passed to the \
             guest command instead of configuring the run. Move it before `--`."
        );
    }
    Ok(())
}

/// Whether `word` reads as a misplaced OCI image reference rather than a
/// program name or a path.
///
/// Parsing alone cannot tell them apart: `ImageReference` accepts almost any
/// bare lowercase word by defaulting it to `docker.io/library/<word>:latest`,
/// so `sh` and `python3` parse just as successfully as `alpine:3.19` does.
/// This additionally requires a marker that a literal command or path never
/// carries — an explicit tag/digest colon, or an explicit registry host
/// before the first `/` — and excludes anything that already reads as a
/// path (`./app`, `/bin/echo`).
fn looks_like_a_misplaced_image_reference(word: &str) -> bool {
    if word.starts_with('.') || word.starts_with('/') {
        return false;
    }
    let has_reference_marker = word.contains(':')
        || word
            .split_once('/')
            .is_some_and(|(host, _rest)| host == "localhost" || host.contains('.'));
    has_reference_marker && word.parse::<mvm_fs::oci::ImageReference>().is_ok()
}

/// With no image source flag given and nothing detected, refuse a first
/// command word that reads as an image reference rather than silently
/// running it as the guest's command.
fn refuse_if_argv_looks_like_an_image_reference(argv: &[String]) -> Result<()> {
    if let Some(first) = argv.first()
        && looks_like_a_misplaced_image_reference(first)
    {
        anyhow::bail!(
            "`{first}` looks like an image reference, not a command — did you mean \
             `--image {first}`?"
        );
    }
    Ok(())
}

/// Merge a catalog entry's declared host-service bindings into the run args.
///
/// The entry declares what the runtime needs; `--host-service` is what the
/// operator asked for. Both end up in the signed plan, so this is a union
/// rather than a default: an operator who passes the flag is adding to the
/// entry's declaration, not replacing it, and neither can silently drop the
/// other's binding.
///
/// Duplicates are dropped here rather than left for
/// `parse_host_service_bindings`, so the count the user sees matches the count
/// the plan carries.
fn adopt_declared_bindings(args: &mut RunArgs, detection: &mvm_core::runtime_catalog::Detection) {
    args.detected_libc = detection.libc;
    for service in &detection.services {
        let raw = service.as_str().to_string();
        if !args.host_service.contains(&raw) {
            args.host_service.push(raw);
        }
    }
}

/// The plain filenames directly in `cwd`.
///
/// Detection reads names only — never contents — so a directory the user merely
/// stood in cannot influence anything but which image is chosen. An unreadable
/// directory detects nothing rather than failing the run.
fn project_files_in(cwd: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(cwd) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

#[cfg(test)]
/// The resolver decides which *source* a run boots from. These pin the
/// order, because the order is the whole contract — and pin that inference
/// never reaches policy.
mod source_resolution {
    use super::*;
    use crate::commands::vm::exec::RunProfile;

    fn touch(dir: &std::path::Path, name: &str) {
        std::fs::write(dir.join(name), b"").expect("write fixture file");
    }

    /// A directory with no `.git` above it, so the manifest walk-up stops
    /// there rather than finding this repo's own `mvm.toml`.
    fn sealed_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::create_dir(dir.path().join(".git")).expect("git boundary");
        dir
    }

    #[test]
    fn an_explicit_image_is_never_second_guessed() {
        let dir = sealed_dir();
        touch(dir.path(), "package.json");
        let mut args = RunArgs {
            image: Some("alpine:3.20".to_string()),
            argv: vec!["npm".to_string()],
            ..Default::default()
        };
        let resolved =
            resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
        assert_eq!(resolved, ResolvedSource::Explicit);
        assert_eq!(args.image.as_deref(), Some("alpine:3.20"));
        assert!(
            resolved.note().is_none(),
            "nothing was inferred to announce"
        );
    }

    #[test]
    fn a_named_runtime_sets_its_image() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            runtime: Some("go".to_string()),
            ..Default::default()
        };
        let resolved =
            resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
        assert!(matches!(resolved, ResolvedSource::Runtime(_)));
        assert_eq!(args.image.as_deref(), Some("golang:1-alpine"));
    }

    #[test]
    fn an_unknown_named_runtime_refuses_rather_than_falling_through() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            runtime: Some("pyhton".to_string()),
            ..Default::default()
        };
        let err =
            resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect_err("must refuse");
        assert!(err.to_string().contains("unknown runtime"), "{err}");
        assert!(
            args.image.is_none(),
            "a refused run must not have chosen an image anyway"
        );
    }

    #[test]
    fn no_detect_leaves_the_bundled_default_even_in_a_project() {
        let dir = sealed_dir();
        touch(dir.path(), "Cargo.toml");
        let mut args = RunArgs {
            no_detect: true,
            argv: vec!["cargo".to_string()],
            ..Default::default()
        };
        let resolved =
            resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
        assert_eq!(resolved, ResolvedSource::BundledDefault);
        assert!(args.image.is_none());
        assert!(args.manifest.is_none());
    }

    #[test]
    fn a_project_manifest_beats_the_runtime_catalog() {
        // The project said what it is; the command is only a hint.
        let dir = sealed_dir();
        std::fs::write(
            dir.path().join("mvm.toml"),
            b"schema_version = 1\nname = \"demo\"\nimage = \"alpine:3.20\"\n",
        )
        .expect("write manifest");
        touch(dir.path(), "package.json");
        let mut args = RunArgs {
            argv: vec!["npm".to_string()],
            ..Default::default()
        };
        let resolved =
            resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
        assert!(matches!(resolved, ResolvedSource::ProjectManifest(_)));
        assert!(args.manifest.is_some());
        assert!(args.image.is_none(), "the manifest supplies the image");
    }

    #[test]
    fn the_catalog_runs_when_there_is_no_manifest() {
        let dir = sealed_dir();
        touch(dir.path(), "Cargo.toml");
        let mut args = RunArgs::default();
        let resolved =
            resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
        assert!(matches!(resolved, ResolvedSource::Runtime(_)));
        assert_eq!(args.image.as_deref(), Some("rust:1-alpine"));
    }

    #[test]
    fn nothing_recognised_falls_back_to_the_bundled_default() {
        let dir = sealed_dir();
        touch(dir.path(), "README.md");
        let mut args = RunArgs {
            argv: vec!["./mystery".to_string()],
            ..Default::default()
        };
        let resolved =
            resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
        assert_eq!(resolved, ResolvedSource::BundledDefault);
        assert!(args.image.is_none());
    }

    /// Inference picks a source. It must not pick a posture: a detected run
    /// carries the same profile and the same deny-all egress as one that
    /// named its image, or "convenience" would be a policy bypass.
    #[test]
    fn a_detected_run_is_still_deny_all_and_standard_profile() {
        let dir = sealed_dir();
        touch(dir.path(), "package.json");
        let mut args = RunArgs::default();
        let before = (args.profile, args.net, args.allow_host.clone());

        resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");

        assert_eq!(args.image.as_deref(), Some("node:22-alpine"));
        assert_eq!(
            (args.profile, args.net, args.allow_host.clone()),
            before,
            "detection changed a policy field"
        );
        assert_eq!(args.profile, RunProfile::Standard);
        assert!(!args.net, "detected runs stay deny-all");
        assert!(args.allow_host.is_empty());
    }

    /// The verb that creates a named machine must not pick its base image
    /// from whatever directory the user happened to be standing in. Before
    /// this split, `machine run` inside any Rust checkout silently chose
    /// `rust:1-alpine`.
    #[test]
    fn explicit_only_ignores_the_working_directory() {
        let dir = sealed_dir();
        touch(dir.path(), "Cargo.toml");
        let mut args = RunArgs {
            argv: vec!["cargo".to_string(), "test".to_string()],
            ..Default::default()
        };
        let resolved =
            resolve_run_source(&mut args, dir.path(), Inference::ExplicitOnly).expect("resolves");
        assert_eq!(resolved, ResolvedSource::BundledDefault);
        assert!(
            args.image.is_none() && args.manifest.is_none(),
            "explicit-only inferred a source anyway"
        );
    }

    /// …but naming one is the user speaking, so it resolves on both verbs.
    #[test]
    fn explicit_only_still_resolves_a_named_runtime() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            runtime: Some("python".to_string()),
            ..Default::default()
        };
        let resolved =
            resolve_run_source(&mut args, dir.path(), Inference::ExplicitOnly).expect("resolves");
        assert!(matches!(resolved, ResolvedSource::Runtime(_)));
        assert_eq!(args.image.as_deref(), Some("python:3.12-alpine"));
    }

    #[test]
    fn an_unreadable_directory_detects_nothing_instead_of_failing() {
        let mut args = RunArgs {
            argv: vec!["./mystery".to_string()],
            ..Default::default()
        };
        let missing = std::path::Path::new("/nonexistent-mvm-detect-fixture");
        // The manifest walk-up canonicalises, so a missing dir is an error
        // there; what must not happen is a panic or a silent image choice.
        let result = resolve_run_source(&mut args, missing, Inference::Enabled);
        assert!(args.image.is_none());
        assert!(result.is_err() || result.expect("ok") == ResolvedSource::BundledDefault);
    }

    /// The exact repro from the issue: `mvmctl machine run app:1.0 -- sh`
    /// gives no image source, so `app:1.0` would otherwise become the guest
    /// command silently.
    #[test]
    fn a_misplaced_image_reference_with_no_source_is_refused() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            argv: vec!["app:1.0".to_string(), "sh".to_string()],
            ..Default::default()
        };
        let err = resolve_run_source(&mut args, dir.path(), Inference::ExplicitOnly)
            .expect_err("a misplaced image reference must refuse");
        assert!(err.to_string().contains("--image app:1.0"), "{err}");
    }

    /// The same refusal applies on `mvmctl run`, where inference actually
    /// runs — it must still fire once the catalog and manifest walk-up both
    /// find nothing, per `resolve_run_source`'s final fallback.
    #[test]
    fn the_refusal_also_fires_once_full_inference_finds_nothing() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            argv: vec!["registry.example.com/app:1.0".to_string()],
            ..Default::default()
        };
        let err = resolve_run_source(&mut args, dir.path(), Inference::Enabled)
            .expect_err("a misplaced image reference must refuse even when inference runs");
        assert!(err.to_string().contains("--image"), "{err}");
    }

    /// Ordinary commands must never trip the hint, including ones a naive
    /// check would flag: a path (`./app`, `/bin/echo`) or a bare word that
    /// happens to parse as a bare image reference (`sh`, `python3` both
    /// parse successfully as `docker.io/library/<word>:latest`).
    #[test]
    fn ordinary_commands_never_trigger_the_image_reference_hint() {
        let dir = sealed_dir();
        for command in ["sh", "python3", "./app", "/bin/echo"] {
            let mut args = RunArgs {
                argv: vec![command.to_string()],
                ..Default::default()
            };
            resolve_run_source(&mut args, dir.path(), Inference::Enabled)
                .unwrap_or_else(|e| panic!("{command:?} must not be refused: {e}"));
        }
    }

    /// A colon-bearing first word still runs once an image source is given —
    /// the hint only fires when nothing else already answered the question.
    #[test]
    fn an_explicit_image_source_bypasses_the_image_reference_hint() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            image: Some("alpine:3.20".to_string()),
            argv: vec!["app:1.0".to_string()],
            ..Default::default()
        };
        let resolved = resolve_run_source(&mut args, dir.path(), Inference::ExplicitOnly)
            .expect("an explicit image source is never second-guessed");
        assert_eq!(resolved, ResolvedSource::Explicit);
    }

    /// A run flag placed right after `--` (the position `trailing_var_arg`
    /// makes ambiguous to the user, not to clap) is refused and named.
    #[test]
    fn a_known_run_flag_right_after_double_dash_is_refused() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            argv: vec!["--image".to_string(), "alpine".to_string()],
            ..Default::default()
        };
        let err = resolve_run_source(&mut args, dir.path(), Inference::Enabled)
            .expect_err("a run flag placed after -- must refuse");
        assert!(err.to_string().contains("--image"), "{err}");
    }

    /// The same flag name deeper in argv is the workload's own business —
    /// only position 0 is unambiguous about what the user just typed after
    /// `--`.
    #[test]
    fn the_same_flag_deeper_in_argv_is_left_to_the_workload() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            argv: vec!["sh".to_string(), "-c".to_string(), "--image".to_string()],
            ..Default::default()
        };
        resolve_run_source(&mut args, dir.path(), Inference::Enabled)
            .expect("a flag deeper in argv is the workload's own business");
    }

    /// A flag-shaped word that is not one of `RunArgs`'s own declared flags
    /// is not ours to refuse — it is passed through to the guest untouched.
    #[test]
    fn an_unrecognised_flag_shaped_word_is_never_refused() {
        let dir = sealed_dir();
        let mut args = RunArgs {
            argv: vec!["--not-a-real-flag".to_string()],
            ..Default::default()
        };
        resolve_run_source(&mut args, dir.path(), Inference::Enabled)
            .expect("an unrecognised flag-shaped word is not one of ours to refuse");
    }
}

#[cfg(test)]
mod declared_binding_tests {
    use super::*;

    fn detection(services: &[&str]) -> mvm_core::runtime_catalog::Detection {
        mvm_core::runtime_catalog::Detection {
            runtime: "svc".to_string(),
            image: "example:1".to_string(),
            libc: mvm_contract::guest_libc::GuestLibc::Musl,
            via: mvm_core::runtime_catalog::DetectedVia::Command("svc".to_string()),
            services: services
                .iter()
                .map(|s| {
                    mvm_contract::protocol::broker::ServiceId::parse(*s).expect("valid service id")
                })
                .collect(),
            peers: Vec::new(),
        }
    }

    #[test]
    fn a_declared_binding_reaches_the_run_args() {
        let mut args = RunArgs::default();
        adopt_declared_bindings(&mut args, &detection(&["host.kv.v1"]));
        assert_eq!(args.host_service, vec!["host.kv.v1".to_string()]);
    }

    /// The entry declares what the runtime needs; the flag is what the
    /// operator asked for. Both reach the signed plan, so neither may drop
    /// the other's binding.
    #[test]
    fn a_declared_binding_and_an_operator_flag_are_unioned() {
        let mut args = RunArgs {
            host_service: vec!["host.time.v1".to_string()],
            ..RunArgs::default()
        };
        adopt_declared_bindings(&mut args, &detection(&["host.kv.v1"]));
        assert_eq!(
            args.host_service,
            vec!["host.time.v1".to_string(), "host.kv.v1".to_string()]
        );
    }

    /// Deduped here rather than downstream, so the count the user sees is the
    /// count the plan carries.
    #[test]
    fn a_binding_declared_and_also_passed_appears_once() {
        let mut args = RunArgs {
            host_service: vec!["host.kv.v1".to_string()],
            ..RunArgs::default()
        };
        adopt_declared_bindings(&mut args, &detection(&["host.kv.v1"]));
        assert_eq!(args.host_service, vec!["host.kv.v1".to_string()]);
    }

    /// The common case: an entry that declares nothing changes nothing, so
    /// every existing `--runtime` invocation keeps its exact posture.
    #[test]
    fn an_entry_declaring_nothing_leaves_the_args_untouched() {
        let mut args = RunArgs::default();
        adopt_declared_bindings(&mut args, &detection(&[]));
        assert!(args.host_service.is_empty());
    }
}
