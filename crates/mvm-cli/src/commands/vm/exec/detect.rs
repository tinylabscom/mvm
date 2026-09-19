//! Which source a run boots from, and what that choice implies.
//!
//! Split out of `exec.rs` because settling a boot source is a self-contained
//! decision: it reads the flags, the working directory and the runtime
//! catalog, and hands back one answer. Everything downstream — admission,
//! launch, teardown — consumes that answer without needing to know how it was
//! reached.

use super::RunArgs;
use anyhow::{Context, Result};
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
/// 3. With no source resolved yet, a first command word that reads as an OCI
///    image reference refuses right here — before any inference runs.
///    Inference is not the user choosing a source, so a project that would
///    otherwise be detected must not race the refusal (see
///    `a_misplaced_image_reference_is_refused_even_inside_a_detected_project`).
/// 4. `--no-detect`, or a verb that only takes explicit sources, stops here.
/// 5. An `mvm.toml` in or above the working directory, found by the same
///    walk-up `mvmctl build` already uses.
/// 6. The command being run, then a project file in the working directory.
/// 7. The bundled default image.
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

    refuse_if_argv_looks_like_an_image_reference(&args.argv, cwd)?;

    if args.no_detect || inference == Inference::ExplicitOnly {
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

    Ok(ResolvedSource::BundledDefault)
}

/// One long spelling (`--name`, or any alias of it) a command accepts.
#[derive(Debug)]
struct LongFlag {
    spelling: String,
    global: bool,
}

/// One short flag (or short alias) a command accepts, and whether it
/// consumes a value — which decides where a cluster like `-dp8080` stops
/// being flags and starts being the value of the last one.
#[derive(Debug, Clone, Copy)]
struct ShortFlag {
    name: char,
    takes_value: bool,
    global: bool,
    /// `-h`/`-V`: left alone on its own, because a workload may forward it
    /// to its own program, but still a switch inside a cluster like `-ih`.
    only_in_a_cluster: bool,
}

/// A token right after `--` that is one of the command's own flags.
#[derive(Debug, PartialEq, Eq)]
struct MisplacedFlag {
    spelling: String,
    global: bool,
}

/// Every flag spelling one `mvmctl` subcommand accepts, read from the built
/// clap command rather than a hand-written list: its own arguments, the
/// top-level `global = true` flags clap propagates into it, the help flag,
/// and every alias (visible or hidden, long or short). A renamed or added
/// flag is therefore picked up automatically.
#[derive(Debug)]
struct KnownFlags {
    verb: String,
    long: Vec<LongFlag>,
    short: Vec<ShortFlag>,
}

impl KnownFlags {
    /// The flags of the subcommand at `path` (`["machine", "run"]`) in the
    /// real `mvmctl` command tree.
    fn of_subcommand(path: &[&str]) -> Result<Self> {
        use clap::CommandFactory;
        let mut root = crate::commands::Cli::command();
        root.build();
        let mut command = &root;
        for name in path {
            command = command
                .find_subcommand(name)
                .with_context(|| format!("`mvmctl` has no `{}` subcommand", path.join(" ")))?;
        }
        Ok(Self::of_command(path.join(" "), command))
    }

    fn of_command(verb: String, command: &clap::Command) -> Self {
        let mut flags = Self {
            verb,
            long: Vec::new(),
            short: Vec::new(),
        };
        for arg in command.get_arguments() {
            flags.add(arg);
        }
        flags
    }

    fn add(&mut self, arg: &clap::Arg) {
        let global = arg.is_global_set();
        let forwardable = matches!(arg.get_id().as_str(), "help" | "version");
        if !forwardable {
            let longs = arg
                .get_long()
                .into_iter()
                .chain(arg.get_all_aliases().into_iter().flatten());
            for long in longs {
                self.long.push(LongFlag {
                    spelling: format!("--{long}"),
                    global,
                });
            }
        }
        let shorts = arg
            .get_short()
            .into_iter()
            .chain(arg.get_all_short_aliases().into_iter().flatten());
        for name in shorts {
            self.short.push(ShortFlag {
                name,
                takes_value: arg.get_action().takes_values(),
                global,
                only_in_a_cluster: forwardable,
            });
        }
    }

    /// The part of `token` that is one of these flags, or `None` when it is
    /// not a flag of this command.
    ///
    /// `--image=alpine` is matched on `--image`. A short token is read the
    /// way clap reads it: a cluster of known switches (`-it`), ending at the
    /// first flag that takes a value, whose value may be attached
    /// (`-p8080:80`, `-dp8080`). Any character that is not a known short flag
    /// before that point means the token is not ours. A standalone `--help`,
    /// `-h`, `--version` or `-V` is left for the workload.
    fn misplaced(&self, token: &str) -> Option<MisplacedFlag> {
        if let Some(long) = token.strip_prefix("--") {
            let spelling = format!("--{}", long.split('=').next().unwrap_or(long));
            let flag = self.long.iter().find(|flag| flag.spelling == spelling)?;
            return Some(MisplacedFlag {
                spelling,
                global: flag.global,
            });
        }
        let cluster = token.strip_prefix('-')?;
        let mut matched: Vec<ShortFlag> = Vec::new();
        for name in cluster.chars() {
            let flag = *self.short.iter().find(|flag| flag.name == name)?;
            matched.push(flag);
            if flag.takes_value {
                break;
            }
        }
        let only_forwardable = matched.len() == 1 && matched[0].only_in_a_cluster;
        if matched.is_empty() || only_forwardable {
            return None;
        }
        Some(MisplacedFlag {
            spelling: std::iter::once('-')
                .chain(matched.iter().map(|f| f.name))
                .collect(),
            global: matched.iter().all(|flag| flag.global),
        })
    }

    /// A known flag placed after `--` lands in the guest argv instead of
    /// configuring the run — silently wrong rather than refused, because
    /// `trailing_var_arg` never reinterprets anything past that point as an
    /// option. Only the token immediately after `--` is checked: a
    /// workload's own program may legitimately take a same-named flag deeper
    /// in its own argv, and position 0 is the program itself, so a leading
    /// `-` there is never a real program name.
    fn refuse_after_double_dash(&self, argv: &[String]) -> Result<()> {
        let Some(found) = argv.first().and_then(|first| self.misplaced(first)) else {
            return Ok(());
        };
        let spelling = &found.spelling;
        let verb = &self.verb;
        let kind = if found.global {
            "a global `mvmctl` flag".to_string()
        } else {
            format!("an `mvmctl {verb}` flag")
        };
        anyhow::bail!(
            "`{spelling}` is {kind}, but it appears right after `--`, so it would be passed to \
             the guest command instead of configuring `mvmctl {verb}`. Move it before `--`."
        )
    }
}

/// `mvmctl run`'s check, against that subcommand's own flags and the global
/// ones.
pub(in crate::commands) fn refuse_run_flag_after_double_dash(argv: &[String]) -> Result<()> {
    KnownFlags::of_subcommand(&["run"])?.refuse_after_double_dash(argv)
}

/// `mvmctl machine run`'s check, against that subcommand's own flags and the
/// global ones.
pub(in crate::commands) fn refuse_machine_run_flag_after_double_dash(
    argv: &[String],
) -> Result<()> {
    KnownFlags::of_subcommand(&["machine", "run"])?.refuse_after_double_dash(argv)
}

/// Whether `word` reads as a misplaced OCI image reference rather than a
/// program name or a path.
///
/// Parsing alone cannot tell them apart: `ImageReference` accepts almost any
/// bare lowercase word by defaulting it to `docker.io/library/<word>:latest`,
/// so `sh` and `python3` parse just as successfully as `alpine:3.19` does.
/// This additionally requires a marker that a literal command or path never
/// carries: an explicit tag/digest colon or `@`, or an explicit registry host
/// before the first `/`. A leading `.` or `/` already reads as a path and is
/// excluded outright. A word that names an existing path relative to `cwd`
/// is never flagged either, whichever marker it carries: `app.d/run` reads
/// like a registry host and `bin/run:dev` like a tag, but a real script must
/// not be refused for its name.
fn looks_like_a_misplaced_image_reference(word: &str, cwd: &std::path::Path) -> bool {
    if word.starts_with('.') || word.starts_with('/') || cwd.join(word).exists() {
        return false;
    }
    let has_marker = word.contains(':')
        || word.contains('@')
        || word
            .split_once('/')
            .is_some_and(|(host, _rest)| host == "localhost" || host.contains('.'));
    has_marker && word.parse::<mvm_fs::oci::ImageReference>().is_ok()
}

/// With no image source flag given, refuse a first command word that reads
/// as an image reference rather than silently running it as the guest's
/// command.
fn refuse_if_argv_looks_like_an_image_reference(
    argv: &[String],
    cwd: &std::path::Path,
) -> Result<()> {
    if let Some(first) = argv.first()
        && looks_like_a_misplaced_image_reference(first, cwd)
    {
        anyhow::bail!(
            "`{first}` looks like an image reference, not a command — did you mean \
             `--image {first}`? A local path escapes the check with a leading `./`."
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
    /// command silently. Exercised with `ExplicitOnly` (no catalog/project
    /// detection to confound it) per the resolver-level testing convention
    /// for this check.
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

    /// The check runs before inference, not after: `mvmctl run node:22 --
    /// node index.js` next to a `package.json` must still refuse rather than
    /// quietly detecting the node runtime and running `node:22` as its
    /// command.
    #[test]
    fn a_misplaced_image_reference_is_refused_even_inside_a_detected_project() {
        let dir = sealed_dir();
        touch(dir.path(), "package.json");
        let mut args = RunArgs {
            argv: vec!["node:22".to_string(), "index.js".to_string()],
            ..Default::default()
        };
        let err = resolve_run_source(&mut args, dir.path(), Inference::Enabled)
            .expect_err("a misplaced image reference must refuse even inside a detected project");
        assert!(err.to_string().contains("--image node:22"), "{err}");
        assert!(
            args.image.is_none(),
            "a refused run must not have chosen an image anyway"
        );
    }

    /// The manifest branch is inference too: an `mvm.toml` must not outrun
    /// the refusal and boot the manifest's image with `node:22` as argv[0].
    #[test]
    fn a_misplaced_image_reference_is_refused_even_beside_a_project_manifest() {
        let dir = sealed_dir();
        std::fs::write(
            dir.path().join("mvm.toml"),
            b"schema_version = 1\nname = \"demo\"\nimage = \"alpine:3.20\"\n",
        )
        .expect("write manifest");
        let mut args = RunArgs {
            argv: vec!["node:22".to_string()],
            ..Default::default()
        };
        let err = resolve_run_source(&mut args, dir.path(), Inference::Enabled)
            .expect_err("a misplaced image reference must refuse beside an mvm.toml");
        assert!(err.to_string().contains("--image node:22"), "{err}");
        assert!(args.manifest.is_none(), "no manifest may have been adopted");
    }

    /// Ordinary commands must never trip the hint. Exercised with
    /// `ExplicitOnly` so the runtime catalog (which does map `sh` to the
    /// `shell` entry) cannot short-circuit the resolver before the check
    /// itself ever runs — `looks_like_a_misplaced_image_reference_tests`
    /// below covers the pure function directly and more exhaustively.
    #[test]
    fn ordinary_commands_never_trigger_the_image_reference_hint() {
        let dir = sealed_dir();
        for command in ["sh", "python3", "./app", "/bin/echo"] {
            let mut args = RunArgs {
                argv: vec![command.to_string()],
                ..Default::default()
            };
            resolve_run_source(&mut args, dir.path(), Inference::ExplicitOnly)
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
}

#[cfg(test)]
mod looks_like_a_misplaced_image_reference_tests {
    use super::*;

    #[test]
    fn negatives_never_trigger() {
        let dir = tempfile::tempdir().expect("tmpdir");
        for word in ["uvicorn", "./bin/app", "/usr/bin/env", "python3"] {
            assert!(
                !looks_like_a_misplaced_image_reference(word, dir.path()),
                "{word:?} must not be flagged"
            );
        }
    }

    /// A dotted first path component reads like a registry host, but a real
    /// relative script must not be flagged just because it exists on disk.
    #[test]
    fn an_existing_relative_path_with_a_dotted_first_segment_is_not_flagged() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::create_dir(dir.path().join("app.d")).expect("mkdir app.d");
        std::fs::write(dir.path().join("app.d").join("run"), b"").expect("write app.d/run");
        assert!(!looks_like_a_misplaced_image_reference(
            "app.d/run",
            dir.path()
        ));
    }

    #[test]
    fn positives_are_flagged() {
        let dir = tempfile::tempdir().expect("tmpdir");
        for word in [
            "node:22",
            "ghcr.io/x/y",
            "localhost/x",
            "x@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                looks_like_a_misplaced_image_reference(word, dir.path()),
                "{word:?} must be flagged"
            );
        }
    }

    /// The same dotted-host word that is flagged when absent must stop being
    /// flagged the moment the matching relative path exists — proves the
    /// existence check, not just the marker, is what decides it.
    #[test]
    fn a_dotted_registry_shaped_word_is_flagged_only_when_the_path_is_absent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        assert!(looks_like_a_misplaced_image_reference(
            "ghcr.io/x/y",
            dir.path()
        ));
        std::fs::create_dir(dir.path().join("ghcr.io")).expect("mkdir");
        std::fs::write(dir.path().join("ghcr.io").join("x"), b"").expect("write");
        // "ghcr.io/x/y" itself still does not exist (only "ghcr.io/x" does),
        // so it is still flagged.
        assert!(looks_like_a_misplaced_image_reference(
            "ghcr.io/x/y",
            dir.path()
        ));
        assert!(!looks_like_a_misplaced_image_reference(
            "ghcr.io/x",
            dir.path()
        ));
    }
    /// The existence guard covers the tag marker too: `bin/run:dev` reads
    /// like `repo:tag`, and is flagged only while no such file exists.
    #[test]
    fn a_colon_bearing_word_is_flagged_only_when_the_path_is_absent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        assert!(looks_like_a_misplaced_image_reference(
            "bin/run:dev",
            dir.path()
        ));
        std::fs::create_dir(dir.path().join("bin")).expect("mkdir bin");
        std::fs::write(dir.path().join("bin").join("run:dev"), b"").expect("write");
        assert!(!looks_like_a_misplaced_image_reference(
            "bin/run:dev",
            dir.path()
        ));
    }
}

#[cfg(test)]
mod flag_after_double_dash_tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_string()).collect()
    }

    fn run_refusal(words: &[&str]) -> Option<String> {
        refuse_run_flag_after_double_dash(&argv(words))
            .err()
            .map(|e| e.to_string())
    }

    fn machine_refusal(words: &[&str]) -> Option<String> {
        refuse_machine_run_flag_after_double_dash(&argv(words))
            .err()
            .map(|e| e.to_string())
    }

    fn assert_refused(refusal: Option<String>, words: &[&str], spelling: &str) {
        let err = refusal.unwrap_or_else(|| panic!("{words:?} must refuse"));
        assert!(err.contains(spelling), "{words:?}: {err}");
    }

    /// Each verb refuses the flag only it declares and passes the other's:
    /// `--mode` exists on `run` alone, `--name` on `machine run` alone. A
    /// verb wired to the wrong argument struct fails one of the four.
    #[test]
    fn each_verb_reads_its_own_argument_struct() {
        assert_refused(run_refusal(&["--mode", "live"]), &["--mode"], "`--mode`");
        assert_eq!(run_refusal(&["--name", "web"]), None);
        assert_refused(machine_refusal(&["--name", "web"]), &["--name"], "`--name`");
        assert_eq!(machine_refusal(&["--mode", "live"]), None);
    }

    /// Flags both verbs share come from `RunArgs`: long, `=`-valued, the
    /// visible alias `--volume`, and the short `-m`.
    #[test]
    fn shared_flags_are_refused_in_every_spelling() {
        let cases: [(&[&str], &str); 4] = [
            (&["--image", "alpine"], "`--image`"),
            (&["--image=alpine"], "`--image`"),
            (&["--volume=/a:/b"], "`--volume`"),
            (&["-m", "mvm.toml"], "`-m`"),
        ];
        for (words, spelling) in cases {
            assert_refused(run_refusal(words), words, spelling);
            assert_refused(machine_refusal(words), words, spelling);
        }
    }

    /// Top-level `global = true` flags are accepted by every subcommand, so
    /// they are just as misplaced after `--`.
    #[test]
    fn global_flags_are_refused() {
        let cases: [(&[&str], &str); 4] = [
            (&["--verbose"], "`--verbose`"),
            (&["--debug"], "`--debug`"),
            (&["-v"], "`-v`"),
            (&["--builder=qemu"], "`--builder`"),
        ];
        for (words, spelling) in cases {
            assert_refused(run_refusal(words), words, spelling);
            assert_refused(machine_refusal(words), words, spelling);
        }
    }

    /// Short flags are read as clap reads them: a cluster of switches, and
    /// an attached value after the first flag that takes one.
    #[test]
    fn short_clusters_and_attached_values_are_refused() {
        let cases: [(&[&str], &str); 4] = [
            (&["-it", "sh"], "`-it`"),
            (&["-p8080:80"], "`-p`"),
            (&["-dp8080:80"], "`-dp`"),
            (&["-mmvm.toml"], "`-m`"),
        ];
        for (words, spelling) in cases {
            assert_refused(machine_refusal(words), words, spelling);
        }
    }

    /// A cluster containing any character that is not one of the verb's
    /// short flags is not ours to refuse.
    #[test]
    fn a_cluster_with_an_unknown_character_is_not_refused() {
        assert_eq!(machine_refusal(&["-iZ"]), None);
        assert_eq!(machine_refusal(&["-"]), None);
        assert_eq!(run_refusal(&["-it"]), None, "`run` has no -i or -t");
    }

    /// `--help` and `--version` on their own are forwarded to the
    /// workload's program.
    #[test]
    fn help_and_version_are_not_refused() {
        for word in ["--help", "-h", "--version", "-V"] {
            assert_eq!(run_refusal(&[word]), None, "{word}");
            assert_eq!(machine_refusal(&[word]), None, "{word}");
        }
    }

    /// Inside a cluster, `h` is the help switch clap would read it as.
    #[test]
    fn help_inside_a_cluster_is_refused() {
        assert_refused(machine_refusal(&["-ih"]), &["-ih"], "`-ih`");
    }

    /// The refusal says which command the flag belongs to, and whether it is
    /// a global flag.
    #[test]
    fn the_refusal_names_the_verb_and_the_kind_of_flag() {
        let verb = machine_refusal(&["--name", "web"]).expect("must refuse");
        assert!(verb.contains("is an `mvmctl machine run` flag"), "{verb}");
        let verb = run_refusal(&["--mode", "live"]).expect("must refuse");
        assert!(verb.contains("is an `mvmctl run` flag"), "{verb}");
        let global = machine_refusal(&["--verbose"]).expect("must refuse");
        assert!(global.contains("is a global `mvmctl` flag"), "{global}");
        assert!(
            global.contains("configuring `mvmctl machine run`"),
            "{global}"
        );
    }

    /// Hidden aliases and short aliases count, not only visible ones. Read
    /// from a synthetic command because no `mvmctl` flag has a hidden alias
    /// today.
    #[test]
    fn hidden_and_short_aliases_are_refused() {
        let command = clap::Command::new("probe").arg(
            clap::Arg::new("image")
                .long("image")
                .alias("img")
                .short_alias('I')
                .action(clap::ArgAction::Set),
        );
        let known = KnownFlags::of_command("probe".to_string(), &command);
        for (token, spelling) in [("--img=alpine", "--img"), ("-I", "-I"), ("-Ialpine", "-I")] {
            let found = known.misplaced(token).expect(token);
            assert_eq!(found.spelling, spelling);
            assert!(!found.global);
        }
    }

    /// The same flag name deeper in argv is the workload's own business —
    /// only position 0 is unambiguous about what the user just typed after
    /// `--`.
    #[test]
    fn the_same_flag_deeper_in_argv_is_left_to_the_workload() {
        assert_eq!(run_refusal(&["sh", "-c", "--image"]), None);
        assert_eq!(machine_refusal(&["sh", "-it"]), None);
    }

    /// A flag-shaped word that no verb declares passes through untouched.
    #[test]
    fn an_unrecognised_flag_shaped_word_is_never_refused() {
        assert_eq!(run_refusal(&["--not-a-real-flag"]), None);
        assert_eq!(machine_refusal(&["--not-a-real-flag"]), None);
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
