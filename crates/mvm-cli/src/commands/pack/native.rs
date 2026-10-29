//! Prepare a digest-pinned native input, then use the shared locked compiler.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Args as ClapArgs;
use flate2::read::GzDecoder;
use mvm_compiler::pack::{PackInput, compile_frozen, lock_pack};
use mvm_contract::pack_spec::{PackSource, PackSpec, PackTarget};
use mvm_core::packs::Sha256Hex;
use mvm_core::plan::EnvironmentDescriptor;
use serde::Deserialize;

const MAX_NATIVE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Existing local-source pack specification.
    #[arg(long, value_name = "FILE")]
    pub spec: PathBuf,
    /// Immutable upstream archive and executable digest records.
    #[arg(long, value_name = "FILE")]
    pub inputs: PathBuf,
    /// Already acquired upstream archive; no network access occurs here.
    #[arg(long, value_name = "FILE")]
    pub archive: PathBuf,
    /// Application launcher to freeze into the source tree.
    #[arg(long, value_name = "FILE")]
    pub launcher: PathBuf,
    /// Package profile to freeze beside the compiled artifact.
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// Signed environment metadata to carry through export.
    #[arg(long, value_name = "FILE")]
    pub environment: PathBuf,
    /// New output directory; an existing path is never replaced.
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
    /// Full commit pin used by the existing compiler.
    #[arg(long, value_name = "COMMIT")]
    pub mvm_revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sha256: Sha256Hex,
    size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Executable {
    member: String,
    sha256: Sha256Hex,
    size: u64,
    interpreter: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema_version: u32,
    upstream_version: String,
    target: PackTarget,
    url: String,
    archive: Record,
    executable: Executable,
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= limit,
        "{} must contain between 1 and {limit} bytes",
        path.display()
    );
    Ok(bytes)
}

fn validate_inputs(pin: &Inputs, spec: &PackSpec) -> Result<()> {
    let url = mvm_http::Url::parse(&pin.url).context("invalid upstream source URL")?;
    ensure!(
        pin.schema_version == 1
            && pin.target == spec.target
            && !pin.upstream_version.is_empty()
            && url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "native input schema, target, version or source URL is invalid"
    );
    ensure!(
        (1..=MAX_NATIVE_BYTES).contains(&pin.archive.size)
            && (1..=MAX_NATIVE_BYTES).contains(&pin.executable.size)
            && !pin.executable.member.is_empty()
            && !pin.executable.member.contains(['/', '\\'])
            && !matches!(pin.executable.member.as_str(), "." | ".."),
        "native input size or member name is invalid"
    );
    ensure!(
        matches!(&spec.source, PackSource::Local { path } if path == "source"),
        "native preparation requires the existing local source path `source`"
    );
    mvm_compiler::pack::lower(spec).context("validating through the shared pack compiler")?;
    Ok(())
}

fn extract_executable(archive: &Path, pin: &Inputs, output: &Path) -> Result<Vec<String>> {
    let mut frozen = tempfile::tempfile().context("creating private archive snapshot")?;
    let copied = std::io::copy(
        &mut File::open(archive)?.take(pin.archive.size + 1),
        &mut frozen,
    )?;
    ensure!(copied == pin.archive.size, "upstream archive size mismatch");
    use std::io::{Seek, SeekFrom};
    frozen.seek(SeekFrom::Start(0))?;
    let digest = mvm_core::crypto::image_verify::sha256_reader(&mut frozen)?;
    ensure!(
        digest == pin.archive.sha256.as_str(),
        "upstream archive digest mismatch"
    );
    frozen.seek(SeekFrom::Start(0))?;
    let mut bundle = tar::Archive::new(GzDecoder::new(frozen));
    let mut entries = bundle.entries()?;
    let mut entry = entries.next().context("native archive is empty")??;
    ensure!(
        entry.header().entry_type().is_file()
            && entry.path()?.as_ref() == Path::new(&pin.executable.member)
            && entry.size() == pin.executable.size,
        "native archive must contain the exact pinned regular executable"
    );
    let mut executable = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let written = std::io::copy(&mut entry, &mut executable)?;
    executable.flush()?;
    drop(entry);
    ensure!(
        entries.next().is_none(),
        "native archive contains extra members"
    );
    ensure!(
        written == pin.executable.size,
        "native executable size mismatch"
    );
    let digest = mvm_core::crypto::image_verify::sha256_file(output)?;
    ensure!(
        digest == pin.executable.sha256.as_str(),
        "native executable digest mismatch"
    );
    let object = read_bounded(output, MAX_NATIVE_BYTES)?;
    let (machine, interpreter) = mvm_fs::elf::loader(&object)?;
    let expected_machine = match pin.target {
        PackTarget::Aarch64Linux => 183,
        PackTarget::X86_64Linux => 62,
    };
    ensure!(
        machine == expected_machine
            && interpreter.as_deref() == Some(pin.executable.interpreter.as_str()),
        "native executable architecture or interpreter differs from its pin"
    );
    mvm_core::private_fs::set_mode(output, 0o755)?;
    Ok(mvm_fs::elf::needed_sonames(&object)?)
}

pub(super) fn run(args: Args) -> Result<()> {
    let spec_bytes = read_bounded(&args.spec, 1024 * 1024)?;
    let spec: PackSpec = serde_json::from_slice(&spec_bytes)?;
    let input_bytes = read_bounded(&args.inputs, 64 * 1024)?;
    let pin: Inputs = serde_json::from_slice(&input_bytes)?;
    validate_inputs(&pin, &spec)?;
    let revision = super::author::parse_revision(&args.mvm_revision)?;
    let environment_bytes = read_bounded(&args.environment, 1024 * 1024)?;
    let environment: EnvironmentDescriptor = serde_json::from_slice(&environment_bytes)?;
    environment.validate()?;
    ensure!(
        environment.pack.as_ref() == Some(&spec.identity)
            && environment.target == spec.target
            && environment.entrypoint.argv == spec.entrypoint
            && environment.resources.as_ref() == Some(&spec.resources),
        "environment identity, target, entrypoint or resources differs from the pack spec"
    );
    let policy = read_bounded(
        &args.policy,
        mvm_core::registry_pack::MAX_APPLICATION_POLICY_BYTES as u64,
    )?;
    let _: mvm_client::policy_profiles::ProfileFile =
        toml::from_str(std::str::from_utf8(&policy)?)?;
    let launcher = read_bounded(&args.launcher, 1024 * 1024)?;
    fs::create_dir(&args.out).context("claiming a new native-source output directory")?;
    mvm_core::private_fs::set_mode(&args.out, 0o700)?;
    let source = args.out.join("source");
    fs::create_dir(&source)?;
    fs::create_dir(source.join("bin"))?;
    let libraries = extract_executable(
        &args.archive,
        &pin,
        &source.join("bin").join(&pin.executable.member),
    )?;
    fs::write(source.join("start"), launcher)?;
    mvm_core::private_fs::set_mode(source.join("start"), 0o755)?;
    fs::write(source.join("inputs.json"), input_bytes)?;
    fs::write(source.join("profile.toml"), &policy)?;
    fs::write(source.join("environment.json"), &environment_bytes)?;
    let input = PackInput {
        spec: &spec,
        spec_dir: &args.out,
        revision: &revision,
    };
    let lock = lock_pack(&input)?;
    compile_frozen(&input, &lock, &args.out.join("artifact"))?;
    fs::write(
        args.out.join(super::author::DEFAULT_LOCK_FILE),
        super::author::render_lock(&lock)?,
    )?;
    fs::write(args.out.join("environment.json"), environment_bytes)?;
    fs::write(args.out.join("profile.toml"), policy)?;
    mvm_core::util::atomic_io::atomic_write_new(&args.out.join("pack.json"), &spec_bytes)?;
    println!(
        "Prepared {}@{} through the shared locked compiler; native libraries: {}",
        spec.identity.name,
        spec.identity.version,
        libraries.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use serde_json::json;

    #[test]
    #[ignore = "requires an explicitly supplied materialized native image and input pin"]
    fn materialized_image_preserves_native_bytes_and_loader_closure() {
        let image = std::env::var("MVM_NATIVE_IMAGE").expect("set MVM_NATIVE_IMAGE");
        let inputs = std::env::var("MVM_NATIVE_INPUTS").expect("set MVM_NATIVE_INPUTS");
        let pin: Inputs =
            serde_json::from_slice(&read_bounded(Path::new(&inputs), 64 * 1024).unwrap()).unwrap();
        let fs = ext4_view::Ext4::load_from_path(&image).unwrap();
        let executable = fs
            .read(format!("/app/bin/{}", pin.executable.member).as_str())
            .unwrap();
        assert_eq!(executable.len() as u64, pin.executable.size);
        assert_eq!(
            mvm_core::crypto::image_verify::sha256_reader(std::io::Cursor::new(&executable))
                .unwrap(),
            pin.executable.sha256.as_str()
        );
        let (_, interpreter) = mvm_fs::elf::loader(&executable).unwrap();
        assert_eq!(
            interpreter.as_deref(),
            Some(pin.executable.interpreter.as_str())
        );
        assert!(
            !fs.read(pin.executable.interpreter.as_str())
                .unwrap()
                .is_empty()
        );
        for library in mvm_fs::elf::needed_sonames(&executable).unwrap() {
            assert!(
                !fs.read(format!("/lib/{library}").as_str())
                    .unwrap()
                    .is_empty(),
                "missing native runtime library {library}"
            );
        }
        assert!(!fs.read("/app/start").unwrap().is_empty());
    }

    fn executable() -> Vec<u8> {
        let path = b"/lib/ld-linux-aarch64.so.1\0";
        let mut bytes = vec![0; 120];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&3u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&120u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&(path.len() as u64).to_le_bytes());
        bytes.extend_from_slice(path);
        bytes
    }

    fn archive(path: &Path, bytes: &[u8], member: &str) -> Record {
        let file = File::create(path).unwrap();
        let mut tar = tar::Builder::new(GzEncoder::new(file, Compression::default()));
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, member, bytes).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        Record {
            sha256: Sha256Hex::from_bytes(&fs::read(path).unwrap()),
            size: fs::metadata(path).unwrap().len(),
        }
    }

    fn pin(record: Record, bytes: &[u8]) -> Inputs {
        Inputs {
            schema_version: 1,
            upstream_version: "1.0.0".into(),
            target: PackTarget::Aarch64Linux,
            url: "https://example.test/releases/1.0.0/native.tar.gz".into(),
            archive: record,
            executable: Executable {
                member: "app".into(),
                sha256: Sha256Hex::from_bytes(bytes),
                size: bytes.len() as u64,
                interpreter: "/lib/ld-linux-aarch64.so.1".into(),
            },
        }
    }

    #[test]
    fn native_extraction_checks_both_digests_and_the_loader() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = executable();
        let path = directory.path().join("native.tar.gz");
        let mut pin = pin(archive(&path, &bytes, "app"), &bytes);
        let output = directory.path().join("app");
        assert!(extract_executable(&path, &pin, &output).unwrap().is_empty());
        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert!(extract_executable(&path, &pin, &output).is_err());
        pin.archive.sha256 = Sha256Hex::from_bytes(b"different archive");
        assert!(extract_executable(&path, &pin, &directory.path().join("wrong")).is_err());
        assert!(!directory.path().join("wrong").exists());
    }

    #[test]
    fn native_preparation_uses_the_locked_compiler_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native.tar.gz");
        let bytes = executable();
        let pin = pin(archive(&path, &bytes, "app"), &bytes);
        let inputs = json!({
            "schema_version": 1, "upstream_version": "1.0.0",
            "target": "aarch64-linux", "url": pin.url,
            "archive": {"sha256": pin.archive.sha256, "size": pin.archive.size},
            "executable": {"member": "app", "sha256": pin.executable.sha256,
                "size": pin.executable.size, "interpreter": pin.executable.interpreter},
        });
        let spec = json!({
            "schema": "mvm.pack-spec/v1",
            "identity": {"name": "agent/environment", "version": "1.0.0"},
            "target": "aarch64-linux",
            "source": {"kind": "local", "path": "source"},
            "packages": [{"name": "bash", "scope": "runtime"}],
            "dependencies": [],
            "copy": [{"source": "bin/app", "destination": "/app/bin/app"}],
            "entrypoint": ["/app/bin/app"],
            "resources": {"cpu_cores": 2, "memory_mb": 4096},
        });
        let environment = json!({
            "descriptor_version": 1,
            "pack": spec["identity"], "target": "aarch64-linux",
            "entrypoint": {"argv": ["/app/bin/app"]},
            "resources": spec["resources"],
        });
        for (name, data) in [
            ("pack.json", spec),
            ("inputs.json", inputs),
            ("environment.json", environment),
        ] {
            fs::write(
                directory.path().join(name),
                serde_json::to_vec(&data).unwrap(),
            )
            .unwrap();
        }
        fs::write(
            directory.path().join("start"),
            b"#!/bin/sh\nexec /app/bin/app\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("profile.toml"),
            b"description = \"agent environment\"\n",
        )
        .unwrap();
        let args = Args {
            spec: directory.path().join("pack.json"),
            inputs: directory.path().join("inputs.json"),
            archive: path,
            launcher: directory.path().join("start"),
            policy: directory.path().join("profile.toml"),
            environment: directory.path().join("environment.json"),
            out: directory.path().join("prepared"),
            mvm_revision: "a".repeat(40),
        };
        run(args.clone()).unwrap();
        assert!(args.out.join("artifact/flake.nix").is_file());
        assert!(args.out.join("pack.lock.json").is_file());
        assert!(args.out.join("pack.json").is_file());
        assert!(run(args.clone()).is_err());
        assert_eq!(fs::read(args.out.join("source/bin/app")).unwrap(), bytes);
    }
}
