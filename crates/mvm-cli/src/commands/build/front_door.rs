use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, ValueEnum};
use mvm_client::bundle::{DebugOutput, HostBundleSigner};
use mvm_client::{OciBundleRequest, export_materialized_oci_bundle, materialize_oci_bundle};
use mvm_contract::pack_spec::PackSpec;
use mvm_core::arch::GuestArch;
use mvm_core::manifest;
use mvm_core::security::AgentProfile;
use mvm_core::user_config::MvmConfig;

use crate::commands::Cli;
use crate::commands::bundle::export::{
    ExportOptions, TemplateExport, export_template, read_environment,
};

const PACK_SCHEMA: &str = "mvm.pack-spec/v1";

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub(in crate::commands) enum SourceKind {
    Pack,
    Manifest,
    Flake,
    Sdk,
    Image,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum BuildSource {
    Pack(PathBuf),
    Manifest(PathBuf),
    Flake(String),
    Sdk(PathBuf),
    Image(String),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Pack, manifest, flake, SDK app, or OCI image to build.
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
    /// Guest architecture for an OCI image; defaults to this host.
    #[arg(long)]
    pub arch: Option<GuestArch>,
    /// Require a digest-pinned, dm-verity-sealed OCI image build.
    #[arg(long)]
    pub production: bool,
    /// Write the OCI bundler's JSON debug report.
    #[arg(long, value_name = "FILE.json")]
    pub debug_out: Option<PathBuf>,
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

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
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
            reject_image_only_flags(&args)?;
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
            reject_image_only_flags(&args)?;
            let slot = super::build::build_manifest_to_slot(&manifest)?;
            export_slot(&slot, out, args.export)
        }
        BuildSource::Flake(reference) => {
            reject_pack_only_flags(&args)?;
            reject_image_only_flags(&args)?;
            let slot = super::build::build_flake_to_slot(&reference, args.profile.as_deref())?;
            export_slot(&slot, out, args.export)
        }
        BuildSource::Sdk(script) => {
            reject_pack_only_flags(&args)?;
            reject_flake_only_flags(&args)?;
            reject_image_only_flags(&args)?;
            build_sdk(cli, cfg, &script, out, args.export)
        }
        BuildSource::Image(reference) => {
            reject_pack_only_flags(&args)?;
            reject_flake_only_flags(&args)?;
            build_image(
                reference,
                out,
                args.arch,
                args.production,
                args.debug_out,
                args.export,
            )
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

fn reject_image_only_flags(args: &Args) -> Result<()> {
    if args.arch.is_some() || args.production || args.debug_out.is_some() {
        bail!("--arch, --production, and --debug-out apply only to image sources");
    }
    Ok(())
}

fn build_sdk(
    cli: &Cli,
    cfg: &MvmConfig,
    script: &Path,
    out: PathBuf,
    options: ExportOptions,
) -> Result<()> {
    let scratch = tempfile::tempdir().context("creating SDK build staging directory")?;
    let compiled = scratch.path().join("compiled");
    super::compile::run(
        cli,
        super::compile::Args {
            entry: Some(script.display().to_string()),
            from_ir: None,
            from_recording: None,
            recording_sha256: None,
            out: compiled.clone(),
            mvm_revision: None,
            mode: None,
            prod: false,
            dev: false,
        },
        cfg,
    )?;
    let reference = compiled
        .to_str()
        .context("SDK staging path is not valid UTF-8")?;
    let slot = super::build::build_flake_to_slot(reference, None)?;
    export_slot(&slot, out, options)
}

fn build_image(
    reference: String,
    out: PathBuf,
    arch: Option<GuestArch>,
    production: bool,
    debug_out: Option<PathBuf>,
    options: ExportOptions,
) -> Result<()> {
    let posture = options.posture_inputs();
    let production = image_is_production(production, posture)?;
    let mut request = OciBundleRequest::new(reference, out)
        .arch(arch.unwrap_or_else(GuestArch::host))
        .production(production)
        .local_build(true);
    if let Some(label) = options.label {
        request = request.label(label);
    }
    if let Some(path) = options.cmdline {
        request = request.cmdline(
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading kernel command line at {}", path.display()))?,
        );
    }
    if let Some(posture) = posture {
        request = request.posture(posture);
    }
    if let Some(path) = options.environment {
        request = request.environment(read_environment(&path)?);
    }
    if let Some(path) = debug_out {
        request = request.debug_out(DebugOutput::json(path));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create OCI materialization runtime")?;
    let materialized = runtime.block_on(materialize_oci_bundle(&request))?;
    let signer = HostBundleSigner::load()?;
    let exported = export_materialized_oci_bundle(&materialized, &signer)?;
    println!("OCI digest: {}", exported.resolved_digest);
    println!("Bundle SHA-256: {}", exported.bundle_sha256);
    println!("Signer key ID: {}", exported.signer_key_id);
    println!("Architecture: {}", exported.arch);
    println!("Output: {}", exported.bundle_path.display());
    Ok(())
}

fn image_is_production(
    requested: bool,
    posture: Option<mvm_client::bundle::PostureInputs>,
) -> Result<bool> {
    if requested && posture.is_some_and(|value| value.profile != AgentProfile::SealedProd) {
        bail!("--production requires --posture sealed-prod when --posture is present");
    }
    Ok(requested || posture.is_some_and(|value| value.profile == AgentProfile::SealedProd))
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
    if !source.exists()
        && let Some(image) = image_reference(source)
    {
        return Ok(BuildSource::Image(image));
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
        if is_sdk_script(source)? {
            matches.push(BuildSource::Sdk(source.to_path_buf()));
        }
    } else if source.is_dir() {
        if let Some(path) = manifest::manifest_in_dir(source)? {
            matches.push(BuildSource::Manifest(path));
        }
        if source.join("flake.nix").is_file() {
            matches.push(BuildSource::Flake(source.display().to_string()));
        }
        if let Some(script) = sdk_script_in_dir(source)? {
            matches.push(BuildSource::Sdk(script));
        }
    }

    match matches.len() {
        0 => bail!(
            "unsupported source {}: tried image, pack, manifest, flake, and sdk detection",
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
        SourceKind::Sdk => Ok(BuildSource::Sdk(resolve_sdk_script(source)?)),
        SourceKind::Image => {
            let value = source.to_str().context("image source is not valid UTF-8")?;
            let image = image_reference(source)
                .with_context(|| format!("invalid image source {value:?}"))?;
            Ok(BuildSource::Image(image))
        }
    }
}

fn image_reference(source: &Path) -> Option<String> {
    let value = source.to_str()?;
    if value.starts_with('.') || value.starts_with('/') || value.is_empty() {
        return None;
    }
    if value.contains("://") || value.parse::<mvm_fs::oci::ImageReference>().is_ok() {
        Some(value.to_string())
    } else {
        None
    }
}

fn resolve_sdk_script(source: &Path) -> Result<PathBuf> {
    if source.is_file() && is_sdk_script(source)? {
        return Ok(source.to_path_buf());
    }
    if source.is_dir()
        && let Some(script) = sdk_script_in_dir(source)?
    {
        return Ok(script);
    }
    bail!(
        "sdk source {} has no statically declared mvm app",
        source.display()
    )
}

fn sdk_script_in_dir(directory: &Path) -> Result<Option<PathBuf>> {
    let entries = std::fs::read_dir(directory)
        .with_context(|| format!("reading SDK source directory {}", directory.display()))?;
    let mut matches = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading an entry in {}", directory.display()))?
            .path();
        if path.is_file() && is_sdk_script(&path)? {
            matches.push(path);
        }
    }
    matches.sort();
    match matches.as_slice() {
        [] => Ok(None),
        [script] => Ok(Some(script.clone())),
        _ => bail!(
            "sdk source {} has multiple statically declared apps: {}",
            directory.display(),
            matches
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn is_sdk_script(path: &Path) -> Result<bool> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading SDK source marker from {}", path.display()))?;
    let parsed = match path.extension().and_then(|extension| extension.to_str()) {
        Some("py") => mvm_compiler::parse_python(&bytes, path),
        Some("ts" | "tsx" | "mts" | "cts") => mvm_compiler::parse_typescript(&bytes, path),
        _ => return Ok(false),
    };
    match parsed {
        Ok(_) => Ok(true),
        Err(mvm_compiler::ParseError::NoDecoratedFunction { .. }) => Ok(false),
        Err(error) => Err(anyhow::anyhow!(error))
            .with_context(|| format!("parsing SDK source marker from {}", path.display())),
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
            Self::Sdk(_) => "sdk",
            Self::Image(_) => "image",
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
        BuildSource::Sdk(script) => script
            .file_stem()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .context("SDK source has no output name")?
            .to_string(),
        BuildSource::Image(reference) => image_output_name(reference)?,
    };
    Ok(PathBuf::from(format!("{name}.mvmpkg")))
}

fn image_output_name(reference: &str) -> Result<String> {
    let without_scheme = reference
        .rsplit_once("://")
        .map_or(reference, |(_, value)| value);
    let repository = without_scheme
        .split('@')
        .next()
        .unwrap_or(without_scheme)
        .rsplit('/')
        .next()
        .context("image source has no repository name")?;
    let name = repository.split(':').next().unwrap_or(repository);
    if name.is_empty() {
        bail!("image source has no repository name");
    }
    Ok(name.to_string())
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

        let image = Harness::try_parse_from([
            "build",
            "ghcr.io/acme/worker:v1",
            "--from",
            "image",
            "--arch",
            "aarch64",
            "--production",
            "--debug-out",
            "build.json",
        ])
        .unwrap()
        .args;
        assert_eq!(image.source_kind, Some(SourceKind::Image));
        assert_eq!(image.arch, Some(GuestArch::Aarch64));
        assert!(image.production);
        assert_eq!(image.debug_out, Some(PathBuf::from("build.json")));
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
    fn source_detection_picks_sdk_files_directories_and_images() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("worker.py");
        write_sdk_script(&script, "worker");
        assert_eq!(
            detect_source(&script, None).unwrap(),
            BuildSource::Sdk(script.clone())
        );
        assert_eq!(
            detect_source(root.path(), None).unwrap(),
            BuildSource::Sdk(script.clone())
        );

        assert_eq!(
            detect_source("ghcr.io/acme/worker:v1", None).unwrap(),
            BuildSource::Image("ghcr.io/acme/worker:v1".to_string())
        );
        assert_eq!(
            detect_source("ghcr.io/acme/worker:v1", Some(SourceKind::Image)).unwrap(),
            BuildSource::Image("ghcr.io/acme/worker:v1".to_string())
        );
        assert_eq!(
            detect_source(root.path(), Some(SourceKind::Sdk)).unwrap(),
            BuildSource::Sdk(script)
        );

        let typescript_root = tempfile::tempdir().unwrap();
        let typescript = typescript_root.path().join("worker.ts");
        fs::write(
            &typescript,
            r#"import * as mvm from "mvm-sdk";
export const worker = mvm.app({
  name: "worker",
  image: mvm.python_image({ python: "3.12" }),
})((value: string): string => value);
"#,
        )
        .unwrap();
        assert_eq!(
            detect_source(&typescript, None).unwrap(),
            BuildSource::Sdk(typescript)
        );
    }

    #[test]
    fn sdk_detection_requires_one_statically_declared_app() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("helper.py"), "print('helper')\n").unwrap();
        let unsupported = detect_source(root.path(), None).unwrap_err().to_string();
        assert!(unsupported.contains("unsupported source"), "{unsupported}");

        write_sdk_script(&root.path().join("one.py"), "one");
        write_sdk_script(&root.path().join("two.py"), "two");
        let multiple = detect_source(root.path(), None).unwrap_err().to_string();
        assert!(
            multiple.contains("multiple statically declared apps"),
            "{multiple}"
        );
        assert!(multiple.contains("one.py"), "{multiple}");
        assert!(multiple.contains("two.py"), "{multiple}");
    }

    #[test]
    fn sdk_participates_in_ambiguous_directory_errors() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("flake.nix"), "{ outputs = _: {}; }\n").unwrap();
        write_sdk_script(&root.path().join("worker.py"), "worker");

        let error = detect_source(root.path(), None).unwrap_err().to_string();
        assert!(error.contains("flake and sdk"), "{error}");
        assert!(error.contains("--from flake|sdk"), "{error}");
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
    fn image_production_and_posture_cannot_conflict() {
        assert!(
            image_is_production(
                true,
                Some(mvm_client::bundle::PostureInputs::new(AgentProfile::Dev))
            )
            .is_err()
        );
        assert!(
            image_is_production(
                false,
                Some(mvm_client::bundle::PostureInputs::new(
                    AgentProfile::SealedProd
                ))
            )
            .unwrap()
        );
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

        assert_eq!(
            default_output(&BuildSource::Sdk(root.path().join("report.py"))).unwrap(),
            PathBuf::from("report.mvmpkg")
        );
        assert_eq!(
            default_output(&BuildSource::Image("ghcr.io/acme/worker:v1".into())).unwrap(),
            PathBuf::from("worker.mvmpkg")
        );
        assert_eq!(
            default_output(&BuildSource::Image(format!(
                "ghcr.io/acme/worker@sha256:{}",
                "ab".repeat(32)
            )))
            .unwrap(),
            PathBuf::from("worker.mvmpkg")
        );
    }

    fn write_sdk_script(path: &Path, name: &str) {
        fs::write(
            path,
            format!(
                r#"import mvm

@mvm.app(name="{name}", image=mvm.python_image(python="3.12"))
def {name}(value: str) -> str:
    return value
"#
            ),
        )
        .unwrap();
    }
}
