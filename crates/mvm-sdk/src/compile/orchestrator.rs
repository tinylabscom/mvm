//! `mvmforge compile`.
//!
//! Reads a validated Workload IR manifest, generates `flake.nix`, `launch.json`,
//! and `workload.json`, and atomically publishes them to the user-specified
//! output directory. No `nix` invocation; no network access.
//!
//! Managed `SecretRef` env bindings are stripped from the
//! baked `launch.json` — the rootfs is secret-free by construction, the guest
//! var is injected as an opaque placeholder only at boot by the substitution
//! endpoint — but preserved in `workload.json`, the host-side admission input
//! `mvmctl up --from-workload-ir` lowers into `plan.secrets` to spawn that
//! endpoint.

use crate::compile::archive::{ArchiveError, archive_dir};
use crate::compile::flake::build_flake_nix;
use crate::compile::func_describe::{FuncDescribeError, describe_function, resolve_module_path};
use crate::compile::launch::build_launch_json;
use crate::compile::reachability::{
    Language, ReachabilityError, detect_language, discover_node_reachable,
    discover_python_reachable,
};
use crate::compile::source::{SourceError, copy_source, rehash};
use crate::ir::{Entrypoint, EnvValue, Source, Workload};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum CompileError {
    OutputExistsNotDir(PathBuf),
    Staging(io::Error),
    /// Stripping build-time framework constructs (`import mvm` /
    /// `@mvm.*`) from the bundled source failed.
    StripFramework(io::Error),
    Render(serde_json::Error),
    Write(io::Error),
    Source(SourceError),
    Reachability(ReachabilityError),
    Archive(ArchiveError),
    /// An Entrypoint::Function declared a
    /// (module, function) that didn't resolve to a top-level
    /// function in the bundled source.
    FunctionNotFound {
        module: String,
        function: String,
    },
    /// The function exists but its parameter
    /// names don't accommodate every name listed in
    /// `args_schema.required`. Functions taking `**kwargs` (Python)
    /// or rest params (JS/TS) bypass this check.
    FunctionSchemaMismatch {
        module: String,
        function: String,
        missing: Vec<String>,
    },
    /// tree-sitter setup or I/O failure while
    /// attempting the function-presence check. Internal-ish; keeps
    /// the surface explicit so callers can distinguish a real
    /// "function missing" from "we couldn't even parse the source".
    FuncDescribe(FuncDescribeError),
    /// A sealed/prod image must declare a workload
    /// entrypoint. The SDK only ever emits sealed images, so an app with
    /// no declared entrypoint can never be compiled into one.
    SealedWorkloadMissingEntrypoint {
        app: String,
    },
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutputExistsNotDir(p) => {
                write!(
                    f,
                    "output path exists and is not a directory: {}",
                    p.display()
                )
            }
            Self::Staging(e) => write!(f, "atomic staging failed: {e}"),
            Self::StripFramework(e) => write!(f, "stripping framework constructs failed: {e}"),
            Self::Render(e) => write!(f, "rendering artifact failed: {e}"),
            Self::Write(e) => write!(f, "writing artifact failed: {e}"),
            Self::Source(e) => write!(f, "source bundling failed: {e}"),
            Self::Reachability(e) => write!(f, "reachability scoping failed: {e}"),
            Self::Archive(e) => write!(f, "archive write failed: {e}"),
            Self::FunctionNotFound { module, function } => write!(
                f,
                "entrypoint function {function:?} not defined at module scope in {module:?}"
            ),
            Self::FunctionSchemaMismatch {
                module,
                function,
                missing,
            } => write!(
                f,
                "function {module:?}:{function:?} is missing parameters required by args_schema: {missing:?}"
            ),
            Self::FuncDescribe(e) => write!(f, "function-presence check: {e}"),
            Self::SealedWorkloadMissingEntrypoint { app } => write!(
                f,
                "sealed/prod workloads must declare an entrypoint; dev images may omit it \
                 for an interactive shell (app {app:?})"
            ),
        }
    }
}

impl std::error::Error for CompileError {}

/// Returns true when `out` should be written as a single deterministic
/// `.tar.gz` rather than as a directory of individual
/// files. Triggered by the `.tar.gz` suffix on the output path. The
/// directory mode remains supported for in-tree consumers like
/// `just real-mvm-check`, which calls `nix flake check` against a
/// directory artifact.
pub fn is_archive_output(out: &Path) -> bool {
    let s = out.to_string_lossy().to_ascii_lowercase();
    s.ends_with(".tar.gz") || s.ends_with(".tgz")
}

/// Compile to a single deterministic `.tar.gz` artifact. The
/// intermediate directory is staged in a tempdir under `out`'s parent
/// so failures don't leave a partial archive in place.
pub fn compile_archive(
    workload: &Workload,
    out: &Path,
    manifest_dir: &Path,
) -> Result<(), CompileError> {
    let tempdir = tempfile::Builder::new()
        .prefix(".mvmforge-archive-staging-")
        .tempdir_in(out.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(CompileError::Staging)?;
    let staging_dir = tempdir.path().join("artifact");
    compile(workload, &staging_dir, manifest_dir)?;
    archive_dir(&staging_dir, out).map_err(CompileError::Archive)?;
    Ok(())
}

/// Compile a validated workload into an artifact directory at `out`.
///
/// Honors `app.source = LocalPath { path, include, exclude }` by
/// copying the source tree into `<staging>/src/` before publishing. `path` in
/// the IR is interpreted relative to `manifest_dir`, or absolute.
pub fn compile(workload: &Workload, out: &Path, manifest_dir: &Path) -> Result<(), CompileError> {
    // Fail closed before any staging/IO. Every SDK
    // artifact is sealed by construction, so an app with no declared
    // entrypoint is a misconfiguration, not a request for an interactive
    // dev shell (that path is the Nix-flake `entrypoint.shell`, never
    // produced here).
    check_declared_entrypoints(workload)?;

    if out.exists() && !out.is_dir() {
        return Err(CompileError::OutputExistsNotDir(out.to_path_buf()));
    }

    let staging = staging_path(out);
    if staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    fs::create_dir_all(&staging).map_err(CompileError::Staging)?;

    let result = (|| -> Result<(), CompileError> {
        let app = workload
            .apps
            .first()
            .expect("validate() ensures at least one app");
        let bundle_dir = staging.join("src");
        let mut source_plan = match &app.source {
            Source::LocalPath {
                path,
                include,
                exclude,
            } => {
                let src_root = resolve_source_path(manifest_dir, path);
                copy_source(&src_root, &bundle_dir, include, exclude)
                    .map_err(CompileError::Source)?
            }
            other => {
                return Err(CompileError::Source(SourceError::PathNotFound(
                    PathBuf::from(format!("(reserved source kind: {other:?})")),
                )));
            }
        };

        // For function-entrypoint
        // workloads, prune language source files unreachable from the
        // declared entry module (plus any declared `extra_imports`).
        // Non-source files (configs, data, lockfiles, etc.) are left
        // untouched — reachability scoping is an import-graph
        // property, not a general file-pruning pass.
        //
        // Language detection: we probe the bundled tree for the
        // entry-module file in each known set of language extensions
        // (Python `.py` first, then Node `.ts`/`.mts`/`.tsx`/etc.).
        // If neither matches, we skip scoping — the user's workload
        // either uses a language we don't support yet (Rust, etc.)
        // or has the entry-module path wrong, in which case the
        // wrapper would fail at runtime anyway.
        // Multi-function apps: each function
        // entrypoint contributes its own root. Walk reachability from
        // every (module, extra_imports) pair and union the results
        // before pruning. Single-entrypoint workloads (the common
        // case) do exactly one walk — same as before.
        let function_eps: Vec<(&String, &Vec<String>)> = app
            .entrypoints
            .iter()
            .filter_map(|ep| match ep {
                Entrypoint::Function {
                    module,
                    extra_imports,
                    ..
                } => Some((module, extra_imports)),
                _ => None,
            })
            .collect();
        if let Some((first_module, _)) = function_eps.first()
            && let Some(lang) = detect_language(&bundle_dir, first_module)
        {
            let mut reachable: HashSet<String> = HashSet::new();
            for (module, extra_imports) in &function_eps {
                let walked = match lang {
                    Language::Python => discover_python_reachable(
                        &bundle_dir,
                        module.as_str(),
                        extra_imports.as_slice(),
                    ),
                    Language::Node => discover_node_reachable(
                        &bundle_dir,
                        module.as_str(),
                        extra_imports.as_slice(),
                    ),
                }
                .map_err(CompileError::Reachability)?;
                reachable.extend(walked);
            }
            // Confirm each entrypoint's
            // (module, function) resolves to a top-level function
            // in the bundled source. Catches typos at compile
            // time rather than the wrapper failing at runtime.
            check_function_presence(&bundle_dir, lang, &app.entrypoints)?;
            prune_unreachable(&bundle_dir, &reachable, lang.extensions())
                .map_err(CompileError::Source)?;
            // The `mvm.app(...)` site is build-time metadata (already lowered
            // to IR above) and returns the function unchanged. Strip the SDK
            // out of the bundled source so the guest runtime never imports it
            // — the wrapper imports the user module to dispatch, and a stray
            // `import mvm` would fail in a rootfs that deliberately doesn't
            // ship the SDK. Python deletes `import mvm` + `@mvm.*` lines; Node
            // additionally unwraps `const NAME = mvm.app({...})(FN)` → `FN`.
            match lang {
                Language::Python => crate::compile::strip_framework::strip_python(&bundle_dir)
                    .map_err(CompileError::StripFramework)?,
                Language::Node => crate::compile::strip_framework::strip_typescript(&bundle_dir)
                    .map_err(CompileError::StripFramework)?,
            }
            source_plan = rehash(&bundle_dir).map_err(CompileError::Source)?;
        }

        // A managed `SecretRef` env binding must never be
        // baked into the image. The guest receives the var only at boot, as an
        // opaque placeholder minted by the per-VM substitution endpoint; the
        // ref itself rides the admission plan (host-side `workload.json`), not
        // the rootfs. Strip every `SecretRef` env entry before rendering the
        // baked artifact so no env-baking path (launch.json → exec wrapper,
        // flake) can ever observe it. The image is secret-free by construction.
        let baked = strip_secret_env(workload);
        let flake = build_flake_nix(&baked).map_err(CompileError::Render)?;
        let launch = build_launch_json(&baked, &source_plan).map_err(CompileError::Render)?;
        write_lf(&staging.join("flake.nix"), &flake)?;
        write_lf(&staging.join("launch.json"), &launch)?;
        // The canonical (unstripped) IR — `mvmctl up --from-workload-ir`'s
        // admission input. Carries the managed `SecretRef`s the baked artifact
        // dropped, so the substitution endpoint is spawned at boot. Host-side
        // only: the flake builds the rootfs from `./src` + `launch.json`, never
        // this file, so it cannot reach the guest.
        let workload_json = serde_json::to_string(workload).map_err(CompileError::Render)?;
        write_lf(&staging.join("workload.json"), &workload_json)?;
        // The rendered flake references
        // `mvm.lib.<system>.mk<Lang>FunctionService` directly. The
        // factories live in mvm; mvmforge does not bundle local
        // copies into the user-visible artifact.
        Ok(())
    })();

    match result {
        Ok(()) => promote(&staging, out),
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            Err(e)
        }
    }
}

/// Refuse to compile any app that lacks a declared
/// workload entrypoint. Reuses the `has_declared_entrypoint` predicate so the
/// "is there a command?" signal has a single definition. Multi-app workloads
/// fail closed on the first offender (named in the error).
fn check_declared_entrypoints(workload: &Workload) -> Result<(), CompileError> {
    for app in &workload.apps {
        if !app.has_declared_entrypoint() {
            return Err(CompileError::SealedWorkloadMissingEntrypoint {
                app: app.name.clone(),
            });
        }
    }
    Ok(())
}

/// Return a clone of `workload` with every managed `SecretRef` env entry
/// removed — from each app's `env` and from each entrypoint's `env`.
/// The baked image must be secret-free; the secret var is delivered
/// only at boot as an opaque placeholder by the substitution endpoint, and the
/// `SecretRef` binding travels the host-side admission plan, never the rootfs.
/// `Literal` env entries are untouched.
fn strip_secret_env(workload: &Workload) -> Workload {
    let mut baked = workload.clone();
    for app in &mut baked.apps {
        retain_non_secret_env(&mut app.env);
        for ep in &mut app.entrypoints {
            match ep {
                Entrypoint::Command { env, .. } | Entrypoint::Function { env, .. } => {
                    retain_non_secret_env(env);
                }
            }
        }
    }
    baked
}

fn retain_non_secret_env(env: &mut std::collections::BTreeMap<String, EnvValue>) {
    env.retain(|_, value| !matches!(value, EnvValue::SecretRef { .. }));
}

/// Confirm every Entrypoint::Function resolves to
/// a top-level function in the bundled source. Runs after reachability
/// (so we've already validated the module file exists) but before
/// pruning (so we still see all source files we might dispatch into).
///
/// Also runs the schema-arity check: when an entrypoint
/// declares `args_schema` with a `required: [...]` list, every name
/// in that list must correspond to a declared parameter on the
/// function (or the function must accept `**kwargs`/rest, in which
/// case the runtime can absorb arbitrary names).
///
/// Errors:
/// - `CompileError::FunctionNotFound` on missing functions →
///   `E_FUNCTION_NOT_FOUND`.
/// - `CompileError::FunctionSchemaMismatch` on schema/signature drift
///   → `E_FUNCTION_SCHEMA_MISMATCH`.
fn check_function_presence(
    bundle_dir: &Path,
    lang: Language,
    entrypoints: &[Entrypoint],
) -> Result<(), CompileError> {
    for ep in entrypoints {
        let Entrypoint::Function {
            module,
            function,
            args_schema,
            ..
        } = ep
        else {
            continue;
        };
        let Some(path) = resolve_module_path(bundle_dir, lang, module) else {
            // Reachability already confirms the entry module exists;
            // a None here means the bundler dropped the file (rare).
            // Skip rather than block — reachability would surface this
            // independently with a clearer error if it were a problem.
            continue;
        };
        let source = fs::read(&path)
            .map_err(|e| CompileError::FuncDescribe(FuncDescribeError::Io(path.clone(), e)))?;
        let described =
            describe_function(lang, &source, function).map_err(CompileError::FuncDescribe)?;
        let Some(sig) = described else {
            return Err(CompileError::FunctionNotFound {
                module: module.clone(),
                function: function.clone(),
            });
        };
        if let Some(schema) = args_schema {
            let missing = schema_required_not_in_signature(schema, &sig);
            if !missing.is_empty() {
                return Err(CompileError::FunctionSchemaMismatch {
                    module: module.clone(),
                    function: function.clone(),
                    missing,
                });
            }
        }
    }
    Ok(())
}

/// Return the names from `args_schema.required[]` that are NOT
/// declared as parameters on `sig`. If the function accepts `**kwargs`
/// or rest, returns empty (variadic absorbs any name). If the schema
/// isn't an object schema with a `required` array, returns empty
/// (we only enforce the strict-required case).
fn schema_required_not_in_signature(
    schema: &crate::ir::JsonSchemaShape,
    sig: &crate::compile::func_describe::FunctionSignature,
) -> Vec<String> {
    if sig.accepts_kwargs {
        return Vec::new();
    }
    let Some(serde_json::Value::Array(required)) = schema.0.get("required") else {
        return Vec::new();
    };
    required
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|name| !sig.param_names.iter().any(|p| p == name))
        .map(String::from)
        .collect()
}

/// Walk `bundle_dir`, deleting every file with one of `prune_exts`
/// whose POSIX-style relative path is not in `reachable`. Other
/// extensions (configs, data files, lockfiles, etc.) are left
/// untouched. Empty directories are removed bottom-up after pruning.
fn prune_unreachable(
    bundle_dir: &Path,
    reachable: &HashSet<String>,
    prune_exts: &[&str],
) -> Result<(), SourceError> {
    fn walk(
        root: &Path,
        cur: &Path,
        reachable: &HashSet<String>,
        prune_exts: &[&str],
    ) -> Result<bool, SourceError> {
        // Returns true if the directory ended up empty after pruning.
        let mut all_removed = true;
        let entries: Vec<_> = fs::read_dir(cur)
            .map_err(|e| SourceError::Copy(cur.to_path_buf(), e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SourceError::Copy(cur.to_path_buf(), e))?;
        for entry in entries {
            let abs = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|e| SourceError::Copy(abs.clone(), e))?;
            if file_type.is_dir() {
                let emptied = walk(root, &abs, reachable, prune_exts)?;
                if emptied {
                    fs::remove_dir(&abs).map_err(|e| SourceError::Copy(abs.clone(), e))?;
                } else {
                    all_removed = false;
                }
            } else if file_type.is_file()
                && abs
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| prune_exts.iter().any(|x| x == &e))
            {
                let rel = abs
                    .strip_prefix(root)
                    .expect("walked under root")
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                if reachable.contains(&rel) {
                    all_removed = false;
                } else {
                    fs::remove_file(&abs).map_err(|e| SourceError::Copy(abs.clone(), e))?;
                }
            } else {
                // Non-source file or symlink — keep.
                all_removed = false;
            }
        }
        Ok(all_removed)
    }
    walk(bundle_dir, bundle_dir, reachable, prune_exts)?;
    Ok(())
}

fn resolve_source_path(manifest_dir: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        manifest_dir.join(p)
    }
}

fn staging_path(out: &Path) -> PathBuf {
    let parent = out.parent().unwrap_or_else(|| Path::new("."));
    let leaf = out
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".to_string());
    parent.join(format!(".{leaf}.mvmforge-staging-{}", std::process::id()))
}

fn promote(staging: &Path, out: &Path) -> Result<(), CompileError> {
    if out.exists() {
        fs::remove_dir_all(out).map_err(CompileError::Staging)?;
    }
    fs::rename(staging, out).map_err(CompileError::Staging)
}

fn write_lf(path: &Path, contents: &str) -> Result<(), CompileError> {
    // Invariant: generated files use LF line endings on every host.
    fs::write(path, contents.replace("\r\n", "\n").as_bytes()).map_err(CompileError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{App, Entrypoint, Format, Image, Resources, SecretMount, SecretRef, Source};
    use tempfile::TempDir;

    fn sample() -> Workload {
        Workload {
            schema_version: "0.1".into(),
            id: "hello".into(),
            apps: vec![App {
                name: "hello".into(),
                source: Source::LocalPath {
                    path: ".".into(),
                    include: vec!["**".into()],
                    exclude: vec![],
                },
                image: Image::NixPackages {
                    packages: vec!["python312".into()],
                },
                entrypoints: vec![Entrypoint::Command {
                    command: vec!["python".into(), "-m".into(), "hello".into()],
                    working_dir: "/app".into(),
                    env: Default::default(),
                }],
                env: Default::default(),
                mounts: vec![],
                network: None,
                resources: Resources {
                    cpu_cores: 1,
                    memory_mb: 256,
                    rootfs_size_mb: 512,
                },
                dependencies: None,
                threat_tier: Default::default(),
                addons: vec![],
                hooks: Default::default(),
            }],
            volumes: vec![],
            extensions: Default::default(),
        }
    }

    fn make_src(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("hello.py"), "print('hi')\n").unwrap();
    }

    #[test]
    fn compile_writes_top_level_entries_atomically() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        compile(&sample(), &out, &manifest_dir).unwrap();
        assert!(out.is_dir());
        assert!(out.join("flake.nix").is_file());
        assert!(out.join("launch.json").is_file());
        assert!(out.join("workload.json").is_file());
        assert!(out.join("src").is_dir());
        let entries: Vec<_> = fs::read_dir(&out).unwrap().collect();
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn compile_is_byte_reproducible() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        compile(&sample(), &a, &manifest_dir).unwrap();
        compile(&sample(), &b, &manifest_dir).unwrap();
        assert_eq!(
            fs::read(a.join("flake.nix")).unwrap(),
            fs::read(b.join("flake.nix")).unwrap()
        );
        assert_eq!(
            fs::read(a.join("launch.json")).unwrap(),
            fs::read(b.join("launch.json")).unwrap()
        );
        assert_eq!(
            fs::read(a.join("src/hello.py")).unwrap(),
            fs::read(b.join("src/hello.py")).unwrap()
        );
    }

    #[test]
    fn compile_overwrites_existing_directory() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("stale.txt"), "stale").unwrap();
        compile(&sample(), &out, &manifest_dir).unwrap();
        assert!(!out.join("stale.txt").exists());
        assert!(out.join("flake.nix").is_file());
    }

    #[test]
    fn compile_rejects_output_that_is_a_file() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("not-a-dir");
        fs::write(&out, "i am a file").unwrap();
        let err = compile(&sample(), &out, &manifest_dir).unwrap_err();
        assert!(matches!(err, CompileError::OutputExistsNotDir(_)));
    }

    fn function_sample() -> Workload {
        let mut w = sample();
        w.apps[0].entrypoints = vec![Entrypoint::Function {
            language: "python".to_string(),
            module: "adder".to_string(),
            function: "add".to_string(),
            format: Format::Json,
            working_dir: "/app".to_string(),
            env: Default::default(),
            args_schema: None,
            return_schema: None,
            extra_imports: vec![],
            primary: true,
            concurrency: None,
        }];
        w
    }

    /// A workload with a managed secret ref compiles into a secret-free
    /// image: the `SecretRef` env entry is stripped from the baked
    /// `launch.json` (the guest var is injected as an opaque placeholder
    /// only at boot, by the substitution endpoint — never baked). The
    /// real value is never in compile's reach; this asserts the *binding*
    /// can't leak into the image either.
    #[test]
    fn compile_strips_secret_refs_from_baked_launch_json() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        let mut workload = sample();
        workload.apps[0].env.insert(
            "API_KEY".into(),
            EnvValue::SecretRef {
                reference: SecretRef {
                    name: "api-key".into(),
                    mount: SecretMount::Env {
                        var: "API_KEY".into(),
                    },
                    auth_type: crate::ir::AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                    sigv4: None,
                },
            },
        );
        // A plain env var alongside the secret must survive untouched.
        workload.apps[0].env.insert(
            "LOG_LEVEL".into(),
            EnvValue::Literal {
                value: "info".into(),
            },
        );

        compile(&workload, &out, &manifest_dir).expect("secret-declaring app compiles");

        let launch: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("launch.json")).unwrap()).unwrap();
        let env = launch.get("env").and_then(|e| e.as_object()).unwrap();
        assert!(
            !env.contains_key("API_KEY"),
            "secret-bound env var must be stripped from the baked image; launch.env = {env:?}"
        );
        assert_eq!(
            env.get("LOG_LEVEL")
                .and_then(|v| v.get("value"))
                .and_then(|v| v.as_str()),
            Some("info"),
            "non-secret env vars must survive the strip"
        );
    }

    /// Compile emits the canonical (unstripped) Workload IR as
    /// `workload.json` alongside the build artifacts. This is the host-side
    /// admission input `mvmctl up --from-workload-ir` lowers into
    /// `plan.secrets` — it carries the managed `SecretRef`s (which were
    /// stripped from the baked `launch.json`) so the substitution endpoint can
    /// be spawned at boot.
    #[test]
    fn compile_emits_workload_json_carrying_secret_refs_for_admission() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        let mut workload = sample();
        workload.apps[0].env.insert(
            "API_KEY".into(),
            EnvValue::SecretRef {
                reference: SecretRef {
                    name: "api-key".into(),
                    mount: SecretMount::Env {
                        var: "API_KEY".into(),
                    },
                    auth_type: crate::ir::AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                    sigv4: None,
                },
            },
        );

        compile(&workload, &out, &manifest_dir).unwrap();

        let ir: Workload =
            serde_json::from_slice(&fs::read(out.join("workload.json")).unwrap()).unwrap();
        // The admission input round-trips the original workload, secrets intact.
        assert_eq!(ir, workload);
        assert!(matches!(
            ir.apps[0].env.get("API_KEY"),
            Some(EnvValue::SecretRef { .. })
        ));
    }

    /// A `SecretRef` carried on an *entrypoint* env (not just the app env)
    /// must also be stripped from the baked `launch.json` — the exec-wrapper
    /// path (`exec.rs::build_guest_wrapper`) exports entrypoint env into the
    /// guest, so a surviving ref there would defeat the invariant.
    #[test]
    fn compile_strips_secret_refs_from_entrypoint_env() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        let mut workload = sample();
        if let Entrypoint::Command { env, .. } = &mut workload.apps[0].entrypoints[0] {
            env.insert(
                "API_KEY".into(),
                EnvValue::SecretRef {
                    reference: SecretRef {
                        name: "api-key".into(),
                        mount: SecretMount::Env {
                            var: "API_KEY".into(),
                        },
                        auth_type: crate::ir::AuthType::Bearer,
                        allowed_hosts: vec!["api.openai.com".into()],
                        sigv4: None,
                    },
                },
            );
        }

        compile(&workload, &out, &manifest_dir).expect("secret-declaring app compiles");

        let launch = String::from_utf8(fs::read(out.join("launch.json")).unwrap()).unwrap();
        assert!(
            !launch.contains("API_KEY")
                && !launch.contains("secret_ref")
                && !launch.contains("\"ref\""),
            "no secret-bound env var or SecretRef may appear anywhere in the baked launch.json: {launch}"
        );
    }

    #[test]
    fn function_workload_compile_does_not_bundle_factories() {
        // Factories live in mvm. The compiled artifact contains zero
        // mvmforge-internal nix files; the rendered flake references
        // upstream `mvm.lib.<system>.mk<Lang>FunctionService` directly.
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        compile(&function_sample(), &out, &manifest_dir).unwrap();
        assert!(
            !out.join("nix").exists(),
            "compiled artifact must not contain a nix/ subtree"
        );
        let flake = fs::read_to_string(out.join("flake.nix")).unwrap();
        assert!(!flake.contains("/nix/factories/"));
        assert!(flake.contains("mvm.lib."));
    }

    #[test]
    fn command_workload_compile_does_not_materialize_internal_files() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        compile(&sample(), &out, &manifest_dir).unwrap();
        assert!(!out.join("nix").exists());
    }

    #[test]
    fn launch_json_is_canonical_and_carries_source_field() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        compile(&sample(), &out, &manifest_dir).unwrap();
        let launch = fs::read_to_string(out.join("launch.json")).unwrap();
        assert!(!launch.contains('\n'));
        assert!(!launch.contains("  "));
        let parsed: serde_json::Value = serde_json::from_str(&launch).unwrap();
        assert_eq!(parsed["workload_id"], "hello");
        assert_eq!(parsed["source"]["kind"], "local_path");
        assert_eq!(parsed["source"]["file_count"], 1);
        assert_eq!(parsed["source"]["tree_hash"].as_str().unwrap().len(), 64);
    }

    // ---------- function-presence check ----------------

    /// Bundles `adder.py` with `def add(a, b)` so reachability + function
    /// presence both have something concrete to operate on.
    fn make_adder_src(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("adder.py"), "def add(a, b):\n    return a + b\n").unwrap();
    }

    fn adder_workload(function_name: &str) -> Workload {
        let mut w = sample();
        w.apps[0].entrypoints = vec![Entrypoint::Function {
            language: "python".to_string(),
            module: "adder".to_string(),
            function: function_name.to_string(),
            format: Format::Json,
            working_dir: "/app".to_string(),
            env: Default::default(),
            args_schema: None,
            return_schema: None,
            extra_imports: vec![],
            primary: true,
            concurrency: None,
        }];
        w
    }

    #[test]
    fn compile_accepts_workload_when_function_exists() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_adder_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        compile(&adder_workload("add"), &out, &manifest_dir).expect("function exists");
    }

    #[test]
    fn compile_rejects_workload_when_function_missing() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_adder_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        let err = compile(&adder_workload("ad"), &out, &manifest_dir).unwrap_err();
        match err {
            CompileError::FunctionNotFound { module, function } => {
                assert_eq!(module, "adder");
                assert_eq!(function, "ad");
            }
            other => panic!("expected FunctionNotFound, got {other:?}"),
        }
    }

    // ---------- schema-arity check -------------------

    /// Build an `adder_workload("add")` and inject an `args_schema` whose
    /// `required: [...]` list we control.
    fn adder_workload_with_schema(required: &[&str]) -> Workload {
        let mut w = adder_workload("add");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {},
            "required": required.to_vec(),
        });
        let serde_json::Value::Object(map) = schema else {
            unreachable!()
        };
        if let Entrypoint::Function { args_schema, .. } = &mut w.apps[0].entrypoints[0] {
            *args_schema = Some(crate::ir::JsonSchemaShape(map));
        }
        w
    }

    #[test]
    fn compile_accepts_when_schema_required_matches_function_params() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_adder_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        // adder.py: def add(a, b)
        compile(
            &adder_workload_with_schema(&["a", "b"]),
            &out,
            &manifest_dir,
        )
        .expect("matching required names should pass");
    }

    #[test]
    fn compile_rejects_when_schema_required_name_not_a_param() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_adder_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        // adder.py: def add(a, b) — the schema demands `c`, which isn't a param.
        let err = compile(
            &adder_workload_with_schema(&["a", "c"]),
            &out,
            &manifest_dir,
        )
        .unwrap_err();
        match err {
            CompileError::FunctionSchemaMismatch {
                module,
                function,
                missing,
            } => {
                assert_eq!(module, "adder");
                assert_eq!(function, "add");
                assert_eq!(missing, vec!["c".to_string()]);
            }
            other => panic!("expected FunctionSchemaMismatch, got {other:?}"),
        }
    }

    // ---------- no-entrypoint policy --------------------

    #[test]
    fn compile_refuses_sealed_workload_with_no_declared_entrypoint() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        let mut workload = sample();
        workload.apps[0].entrypoints = vec![];

        let err = compile(&workload, &out, &manifest_dir).unwrap_err();
        match &err {
            CompileError::SealedWorkloadMissingEntrypoint { app } => {
                assert_eq!(app, "hello");
            }
            other => panic!("expected SealedWorkloadMissingEntrypoint, got {other:?}"),
        }
        assert!(
            err.to_string()
                .contains("sealed/prod workloads must declare an entrypoint"),
            "message was: {err}"
        );
    }

    #[test]
    fn compile_refuses_second_app_missing_entrypoint_and_names_it() {
        // Guard iterates all apps, not just the first — a valid app[0] must
        // not mask an empty app[1]. The named offender is the second app.
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        let mut workload = sample();
        let mut second = workload.apps[0].clone();
        second.name = "sidecar".into();
        second.entrypoints = vec![];
        workload.apps.push(second);

        let err = compile(&workload, &out, &manifest_dir).unwrap_err();
        match &err {
            CompileError::SealedWorkloadMissingEntrypoint { app } => {
                assert_eq!(app, "sidecar");
            }
            other => panic!("expected SealedWorkloadMissingEntrypoint, got {other:?}"),
        }
    }

    #[test]
    fn compile_accepts_idle_sleep_infinity_command() {
        // An idle image declares a real command, so the no-entrypoint guard
        // must not fire. We assert specifically on the ABSENCE of that error —
        // a bare `sleep infinity` source tree compiles cleanly here.
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        make_src(&manifest_dir);
        let out = tmp.path().join("artifact");
        let mut workload = sample();
        workload.apps[0].entrypoints = vec![Entrypoint::Command {
            command: vec!["sleep".into(), "infinity".into()],
            working_dir: "/app".into(),
            env: Default::default(),
        }];

        match compile(&workload, &out, &manifest_dir) {
            Ok(()) => {}
            Err(CompileError::SealedWorkloadMissingEntrypoint { .. }) => {
                panic!("idle sleep-infinity command must not trip the B3 guard")
            }
            Err(other) => panic!("unexpected unrelated compile error: {other:?}"),
        }
    }

    #[test]
    fn compile_accepts_schema_required_when_function_takes_kwargs() {
        let tmp = TempDir::new().unwrap();
        let manifest_dir = tmp.path().join("manifest");
        // Variadic `**kwargs` absorbs any required name.
        fs::create_dir_all(&manifest_dir).unwrap();
        fs::write(
            manifest_dir.join("adder.py"),
            "def add(**kwargs):\n    return sum(kwargs.values())\n",
        )
        .unwrap();
        let out = tmp.path().join("artifact");
        compile(
            &adder_workload_with_schema(&["x", "y", "totally_unrelated"]),
            &out,
            &manifest_dir,
        )
        .expect("kwargs-accepting function should bypass the schema check");
    }
}
