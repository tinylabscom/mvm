use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, ValueEnum};
use mvm_contract::pack_spec::PackSpec;
use mvm_core::manifest;
use mvm_core::user_config::MvmConfig;

use crate::commands::Cli;
use crate::commands::bundle::export::{ExportOptions, TemplateExport, export_template};

const PACK_SCHEMA: &str = "mvm.pack-spec/v1";

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub(in crate::commands) enum SourceKind {
    Pack,
    Manifest,
    Flake,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum BuildSource {
    Pack(PathBuf),
    Manifest(PathBuf),
    Flake(String),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Pack spec, manifest project, or Nix flake directory to build.
    #[arg(default_value = ".", value_name = "SOURCE")]
    pub source: PathBuf,
    /// New archive path; defaults to ./<source-name>.mvmpkg.
    #[arg(long, value_name = "FILE.mvmpkg")]
    pub out: Option<PathBuf>,
    /// Force one source class instead of detecting it.
    #[arg(long = "from", value_enum, value_name = "KIND")]
    pub source_kind: Option<SourceKind>,
    /// Explicit Nix flake reference; bypasses filesystem source detection.
    #[arg(long, value_name = "REF")]
    pub flake: Option<String>,
    /// Flake package profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Pack lock; defaults to pack.lock.json beside a pack spec.
    #[arg(long, value_name = "FILE")]
    pub lock: Option<PathBuf>,
    /// Seconds the pack health entrypoint may run.
    #[arg(long, default_value_t = 120)]
    pub health_timeout: u64,
    /// Hypervisor used for a pack health boot.
    #[arg(long)]
    pub hypervisor: Option<String>,
    /// Write bounded frozen-input diagnostics for a pack build.
    #[arg(long, value_name = "PATH")]
    pub input_observation: Option<PathBuf>,
    /// Allow a local mvm-images builder-image build for this invocation.
    #[arg(long)]
    pub allow_local_builder_build: bool,
    #[command(flatten)]
    pub export: ExportOptions,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let source = match args.flake.as_deref() {
        Some(reference) => {
            if args.source != Path::new(".") {
                bail!("SOURCE and --flake cannot be used together");
            }
            if args
                .source_kind
                .is_some_and(|kind| kind != SourceKind::Flake)
            {
                bail!("--flake requires --from flake when --from is present");
            }
            detect_forced(Path::new(reference), SourceKind::Flake)?
        }
        None => detect_source(&args.source, args.source_kind)?,
    };
    let out = args.out.clone().unwrap_or(default_output(&source)?);

    match source {
        BuildSource::Pack(spec) => {
            reject_flake_only_flags(&args)?;
            crate::commands::pack::build::run_for_front_door(
                crate::commands::pack::build::BuildArgs {
                    spec,
                    lock: args.lock,
                    out,
                    health_timeout: args.health_timeout,
                    hypervisor: args.hypervisor,
                    input_observation: args.input_observation,
                },
                args.export,
            )
        }
        BuildSource::Manifest(manifest) => {
            reject_pack_only_flags(&args)?;
            reject_flake_only_flags(&args)?;
            let slot = super::build::build_manifest_to_slot(&manifest)?;
            export_slot(&slot, out, args.export)
        }
        BuildSource::Flake(reference) => {
            reject_pack_only_flags(&args)?;
            let slot = super::build::build_flake_to_slot(&reference, args.profile.as_deref())?;
            export_slot(&slot, out, args.export)
        }
    }
}

fn reject_pack_only_flags(args: &Args) -> Result<()> {
    if args.lock.is_some() || args.hypervisor.is_some() || args.input_observation.is_some() {
        bail!("--lock, --hypervisor, and --input-observation apply only to pack sources");
    }
    if args.health_timeout != 120 {
        bail!("--health-timeout applies only to pack sources");
    }
    Ok(())
}

fn reject_flake_only_flags(args: &Args) -> Result<()> {
    if args.profile.is_some() {
        bail!("--profile applies only to flake sources");
    }
    Ok(())
}

fn export_slot(slot: &str, out: PathBuf, options: ExportOptions) -> Result<()> {
    let mut export = options.apply(TemplateExport::new(out))?;
    export.local_build = true;
    let exported = export_template(slot, export)?;
    println!(
        "Built local archive {} ({} bytes, key_id={})",
        exported.path.display(),
        exported.size_bytes,
        exported.key_id.0
    );
    Ok(())
}

pub(in crate::commands) fn detect_source(
    source: impl AsRef<Path>,
    forced: Option<SourceKind>,
) -> Result<BuildSource> {
    let source = source.as_ref();
    if let Some(kind) = forced {
        return detect_forced(source, kind);
    }
    if !source.exists() {
        bail!("source not found: {}", source.display());
    }

    let mut matches = Vec::new();
    if source.is_file() {
        if has_pack_schema(source)? {
            matches.push(BuildSource::Pack(source.to_path_buf()));
        }
        if is_manifest_name(source) {
            matches.push(BuildSource::Manifest(source.to_path_buf()));
        }
    } else if source.is_dir() {
        if let Some(path) = manifest::manifest_in_dir(source)? {
            matches.push(BuildSource::Manifest(path));
        }
        if source.join("flake.nix").is_file() {
            matches.push(BuildSource::Flake(source.display().to_string()));
        }
    }

    match matches.len() {
        0 => bail!(
            "unsupported source {}: tried pack, manifest, and flake detection",
            source.display()
        ),
        1 => Ok(matches.remove(0)),
        _ => {
            let names = matches
                .iter()
                .map(BuildSource::kind_name)
                .collect::<Vec<_>>();
            bail!(
                "ambiguous source {}: matched {}; use --from {}",
                source.display(),
                names.join(" and "),
                names.join("|")
            )
        }
    }
}

fn detect_forced(source: &Path, kind: SourceKind) -> Result<BuildSource> {
    match kind {
        SourceKind::Pack => {
            if !source.is_file() {
                bail!("pack source not found: {}", source.display());
            }
            if !has_pack_schema(source)? {
                bail!(
                    "{} does not declare schema {PACK_SCHEMA:?}",
                    source.display()
                );
            }
            Ok(BuildSource::Pack(source.to_path_buf()))
        }
        SourceKind::Manifest => {
            let path = mvm_core::manifest::resolve_manifest_config_path(source)
                .with_context(|| format!("resolving manifest source {}", source.display()))?;
            Ok(BuildSource::Manifest(path))
        }
        SourceKind::Flake => {
            let value = source
                .to_str()
                .context("flake source is not valid UTF-8")?
                .to_string();
            if source.exists() && !source.join("flake.nix").is_file() {
                bail!("flake source {} has no flake.nix", source.display());
            }
            mvm_core::naming::validate_flake_ref(&value)
                .with_context(|| format!("invalid flake source {value:?}"))?;
            Ok(BuildSource::Flake(value))
        }
    }
}

fn has_pack_schema(path: &Path) -> Result<bool> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading source marker from {}", path.display()))?;
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(false);
    };
    Ok(value.get("schema").and_then(serde_json::Value::as_str) == Some(PACK_SCHEMA))
}

fn is_manifest_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "mvm.toml" | "Mvmfile.toml"))
}

impl BuildSource {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Pack(_) => "pack",
            Self::Manifest(_) => "manifest",
            Self::Flake(_) => "flake",
        }
    }
}

pub(in crate::commands) fn default_output(source: &BuildSource) -> Result<PathBuf> {
    let name = match source {
        BuildSource::Pack(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading pack spec {}", path.display()))?;
            let spec: PackSpec = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing pack spec {}", path.display()))?;
            spec.identity
                .name
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .context("pack identity has no output name")?
                .to_string()
        }
        BuildSource::Manifest(path) => path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .context("manifest source has no project directory name")?
            .to_string(),
        BuildSource::Flake(reference) => flake_output_name(reference)?,
    };
    Ok(PathBuf::from(format!("{name}.mvmpkg")))
}

fn flake_output_name(reference: &str) -> Result<String> {
    let path = Path::new(reference);
    if path.exists() {
        return std::fs::canonicalize(path)
            .with_context(|| format!("canonicalizing flake source {reference:?}"))?
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .context("flake source has no output name");
    }
    reference
        .split(['/', '#'])
        .rfind(|part| !part.is_empty())
        .map(str::to_string)
        .context("flake source has no output name")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn build_cli_defaults_to_dot_and_accepts_shared_export_flags() {
        let defaults = Harness::try_parse_from(["build"]).unwrap().args;
        assert_eq!(defaults.source, PathBuf::from("."));
        assert!(defaults.out.is_none());

        let parsed = Harness::try_parse_from([
            "build",
            "project",
            "--out",
            "dist/app.mvmpkg",
            "--from",
            "flake",
            "--label",
            "worker",
            "--posture",
            "dev",
            "--allow-egress",
        ])
        .unwrap()
        .args;
        assert_eq!(parsed.source, PathBuf::from("project"));
        assert_eq!(parsed.out, Some(PathBuf::from("dist/app.mvmpkg")));
        assert_eq!(parsed.source_kind, Some(SourceKind::Flake));
        assert_eq!(parsed.export.label.as_deref(), Some("worker"));
        assert!(parsed.export.allow_egress);
    }

    #[test]
    fn source_detection_picks_pack_manifest_and_flake() {
        let root = tempfile::tempdir().unwrap();
        let pack = root.path().join("pack.json");
        fs::write(
            &pack,
            r#"{"schema":"mvm.pack-spec/v1","author_code":"must not run"}"#,
        )
        .unwrap();
        assert_eq!(detect_source(&pack, None).unwrap(), BuildSource::Pack(pack));

        let manifest_dir = root.path().join("manifest-app");
        fs::create_dir(&manifest_dir).unwrap();
        fs::write(manifest_dir.join("mvm.toml"), "schema_version = 1\n").unwrap();
        assert_eq!(
            detect_source(&manifest_dir, None).unwrap(),
            BuildSource::Manifest(manifest_dir.join("mvm.toml"))
        );

        let flake_dir = root.path().join("flake-app");
        fs::create_dir(&flake_dir).unwrap();
        fs::write(flake_dir.join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
        assert_eq!(
            detect_source(&flake_dir, None).unwrap(),
            BuildSource::Flake(flake_dir.display().to_string())
        );
    }

    #[test]
    fn ambiguous_directory_names_matches_and_disambiguation_flag() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("mvm.toml"), "schema_version = 1\n").unwrap();
        fs::write(root.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();

        let error = detect_source(root.path(), None).unwrap_err().to_string();
        assert!(error.contains("ambiguous source"), "{error}");
        assert!(error.contains("manifest"), "{error}");
        assert!(error.contains("flake"), "{error}");
        assert!(error.contains("--from manifest|flake"), "{error}");

        assert!(matches!(
            detect_source(root.path(), Some(SourceKind::Manifest)).unwrap(),
            BuildSource::Manifest(_)
        ));
        assert!(matches!(
            detect_source(root.path(), Some(SourceKind::Flake)).unwrap(),
            BuildSource::Flake(_)
        ));
    }

    #[test]
    fn missing_and_unsupported_sources_are_distinct() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let missing_error = detect_source(&missing, None).unwrap_err().to_string();
        assert!(
            missing_error.contains("source not found"),
            "{missing_error}"
        );
        assert!(
            missing_error.contains(&missing.display().to_string()),
            "{missing_error}"
        );

        let unsupported = root.path().join("notes.txt");
        fs::write(&unsupported, "hello\n").unwrap();
        let unsupported_error = detect_source(&unsupported, None).unwrap_err().to_string();
        assert!(
            unsupported_error.contains("unsupported source"),
            "{unsupported_error}"
        );
        assert!(
            unsupported_error.contains(&unsupported.display().to_string()),
            "{unsupported_error}"
        );
    }

    #[test]
    fn profile_is_refused_for_non_flake_sources() {
        let args = Harness::try_parse_from(["build", "project", "--profile", "server"])
            .unwrap()
            .args;
        let error = reject_flake_only_flags(&args).unwrap_err().to_string();
        assert_eq!(error, "--profile applies only to flake sources");
    }

    #[test]
    fn default_output_uses_the_source_name() {
        let root = tempfile::tempdir().unwrap();
        let pack = root.path().join("pack.json");
        fs::write(
            &pack,
            r#"{
              "schema":"mvm.pack-spec/v1",
              "identity":{"name":"acme/reporting","version":"1.0.0"},
              "target":"aarch64-linux",
              "source":{"kind":"local","path":"."},
              "packages":[],"dependencies":[],"copy":[],
              "entrypoint":["/bin/true"],
              "resources":{"cpu_cores":1,"memory_mb":128}
            }"#,
        )
        .unwrap();
        assert_eq!(
            default_output(&BuildSource::Pack(pack)).unwrap(),
            PathBuf::from("reporting.mvmpkg")
        );

        let manifest = root.path().join("weather").join("mvm.toml");
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(&manifest, "schema_version = 1\n").unwrap();
        assert_eq!(
            default_output(&BuildSource::Manifest(manifest)).unwrap(),
            PathBuf::from("weather.mvmpkg")
        );

        assert_eq!(
            default_output(&BuildSource::Flake("github:acme/worker".into())).unwrap(),
            PathBuf::from("worker.mvmpkg")
        );
    }
}
