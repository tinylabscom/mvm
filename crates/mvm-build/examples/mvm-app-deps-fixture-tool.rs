//! Fixture-sealer + gate-probe helper for the `app-deps-audit` CI
//! smoke harness.
//!
//! The harness needs to (a) seal realistic sealed-volume fixtures into
//! a scratch deps-volumes cache, (b) drive the prod/dev gate against
//! those fixtures, and (c) round-trip the inspect path against a
//! freshly sealed volume. None of (a)/(b)/(c) requires a builder VM —
//! the wire shape is what `mvm_sdk::compile::deps_audit::seal_volume`
//! produces, so re-using the same sealer here keeps the smoke aligned
//! with the supervisor's verifier and the builder VM's emitter.
//!
//! This is **not** a library binary. It exists only so the shell-level
//! CI smoke (`scripts/test-app-deps-ci-gate.sh`) can drive the same
//! Rust paths the unit tests cover without dragging shell into test-
//! only code (the test harnesses in `crates/mvm-build/tests/` aren't
//! invokable from a shell directly).
//!
//! Verbs:
//!
//! - `seal-clean --cache-root <dir> --out-json <file>` — seal a clean
//!   sealed volume (no CVE findings, realistic SBOM + fetch log).
//!   Writes the `{ volume_hash, volume_dir, manifest_sha256 }` triple
//!   to `--out-json` so the shell can pick it up.
//!
//! - `seal-with-high-cve --cache-root <dir> --out-json <file>` —
//!   same, but `cve.json` carries one HIGH-severity finding.
//!
//! - `gate-check --cache-root <dir> --volume-hash <hash> --gate prod|dev`
//!   — load the sealed volume from `<cache-root>/<hash>/`, build an
//!   `InstallResult` referring to it, and run `apply_install_gate`.
//!   Exits 0 when the gate ACCEPTS, exits 1 when it REJECTS (so
//!   shell scripts can compose with `if`/`! cmd`).
//!
//! All paths are explicit on the CLI so the binary never reaches
//! into a user's real `~/.mvm/` cache by accident.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mvm_build::app_deps::{GateLevel, InstallResult};
use mvm_build::app_deps_gate::apply_install_gate;
use mvm_sdk::compile::deps_audit::{
    FILE_CONTENT_DIR, FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, seal_volume,
};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        usage();
        return ExitCode::from(2);
    }
    let verb = argv[1].as_str();
    let rest = &argv[2..];
    let outcome = match verb {
        "seal-clean" => seal_clean(rest),
        "seal-with-high-cve" => seal_with_high_cve(rest),
        "gate-check" => gate_check(rest),
        "help" | "--help" | "-h" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("error: unknown verb: {other}");
            usage();
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!(
        "usage:\n\
         \x20 seal-clean         --cache-root <dir> --out-json <file>\n\
         \x20 seal-with-high-cve --cache-root <dir> --out-json <file>\n\
         \x20 gate-check         --cache-root <dir> --volume-hash <hash> --gate prod|dev"
    );
}

fn parse_kv<'a>(rest: &'a [String], key: &str) -> Result<&'a str, String> {
    let needle = format!("--{key}");
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == needle {
            return rest
                .get(i + 1)
                .map(String::as_str)
                .ok_or_else(|| format!("--{key} requires a value"));
        }
        i += 1;
    }
    Err(format!("missing required arg: --{key}"))
}

/// Synthesize a clean realistic SBOM + fetch log + CVE result, seal
/// the volume, write it under `<cache-root>/<volume_hash>/`, and emit
/// a JSON pointer to `--out-json` for the shell harness.
fn seal_clean(rest: &[String]) -> Result<ExitCode, String> {
    let cache_root = PathBuf::from(parse_kv(rest, "cache-root")?);
    let out_json = PathBuf::from(parse_kv(rest, "out-json")?);
    let sealed = seal_into_cache(&cache_root, /* high_cve */ false)?;
    write_seal_pointer(&out_json, &sealed)?;
    Ok(ExitCode::SUCCESS)
}

fn seal_with_high_cve(rest: &[String]) -> Result<ExitCode, String> {
    let cache_root = PathBuf::from(parse_kv(rest, "cache-root")?);
    let out_json = PathBuf::from(parse_kv(rest, "out-json")?);
    let sealed = seal_into_cache(&cache_root, /* high_cve */ true)?;
    write_seal_pointer(&out_json, &sealed)?;
    Ok(ExitCode::SUCCESS)
}

/// Re-use `mvm_sdk::compile::deps_audit::seal_volume` to produce a
/// volume the way the builder VM's `mvm-host-vm-init::install::seal`
/// would. Realistic-ish payloads so the inspector pretty-print works
/// against fields it would see in production (component_count > 0,
/// host count > 0).
fn seal_into_cache(cache_root: &Path, high_cve: bool) -> Result<SealOutcome, String> {
    fs::create_dir_all(cache_root).map_err(|e| format!("mkdir {}: {e}", cache_root.display()))?;
    let scratch = tempfile::tempdir_in(cache_root).map_err(|e| format!("scratch tempdir: {e}"))?;
    let scratch_path = scratch.path();

    // content/ — a few "files" representing an installed site-packages.
    let content_dir = scratch_path.join(FILE_CONTENT_DIR);
    fs::create_dir_all(content_dir.join("requests")).map_err(|e| format!("mkdir requests: {e}"))?;
    fs::write(
        content_dir.join("requests").join("__init__.py"),
        b"__version__ = '2.32.3'\n",
    )
    .map_err(|e| format!("write requests/__init__.py: {e}"))?;
    fs::write(
        content_dir.join("requests-2.32.3.dist-info"),
        b"Metadata-Version: 2.1\nName: requests\n",
    )
    .map_err(|e| format!("write dist-info: {e}"))?;

    // SBOM: realistic CycloneDX 1.5 with one component so the inspector
    // reports component_count > 0 (the empty-stub shape would trip the
    // prod gate's `MissingSbom`).
    let sbom_body = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.32.3",
                "purl": "pkg:pypi/requests@2.32.3"
            }
        ]
    });
    let sbom = scratch_path.join(FILE_SBOM);
    fs::write(&sbom, serde_json::to_vec_pretty(&sbom_body).unwrap())
        .map_err(|e| format!("write sbom: {e}"))?;

    // fetch.log: a handful of `pypi.org` + `files.pythonhosted.org`
    // URLs so `inspect.fetch_log.line_count > 0`.
    let fetch_log = scratch_path.join(FILE_FETCH_LOG);
    fs::write(
        &fetch_log,
        b"GET https://pypi.org/simple/requests/\n\
          GET https://files.pythonhosted.org/packages/f9/9b/.../requests-2.32.3-py3-none-any.whl\n\
          GET https://pypi.org/simple/certifi/\n\
          GET https://files.pythonhosted.org/packages/12/90/.../certifi-2024.8.30-py3-none-any.whl\n",
    )
    .map_err(|e| format!("write fetch.log: {e}"))?;

    // CVE: clean variant emits realistic pip-audit shape with no
    // findings; the high-cve variant inserts one HIGH severity row
    // so the prod gate refuses it.
    let cve_body = if high_cve {
        serde_json::json!({
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.32.3",
                    "vulns": [
                        {
                            "id": "PYSEC-XXXX-9999",
                            "fix_versions": ["99.0.0"],
                            "aliases": ["CVE-XXXX-9999"],
                            "description": "synthetic high-severity finding for CI",
                            "severity": "high"
                        }
                    ]
                }
            ]
        })
    } else {
        serde_json::json!({
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.32.3",
                    "vulns": []
                }
            ]
        })
    };
    let cve = scratch_path.join(FILE_CVE);
    fs::write(&cve, serde_json::to_vec_pretty(&cve_body).unwrap())
        .map_err(|e| format!("write cve.json: {e}"))?;

    let mut annotations = BTreeMap::new();
    annotations.insert("language".to_string(), "python".to_string());
    annotations.insert("gate".to_string(), "dev".to_string());
    annotations.insert(
        "fixture_kind".to_string(),
        if high_cve {
            "high-cve".into()
        } else {
            "clean".into()
        },
    );

    let sealed = seal_volume(
        &content_dir,
        &sbom,
        &fetch_log,
        &cve,
        "2026-05-14T00:00:00Z",
        annotations,
    )
    .map_err(|e| format!("seal_volume: {e}"))?;

    // Rename `<scratch>/` into `<cache_root>/<volume_hash>/` and drop
    // `meta.json` inside. Matches the orchestrator's seal-into-cache
    // sequence (`run_install_via_driver`).
    let final_dir = cache_root.join(&sealed.volume_hash);
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir)
            .map_err(|e| format!("rm-rf existing {}: {e}", final_dir.display()))?;
    }
    // We can't rename a TempDir's path directly; copy then drop.
    fs::create_dir_all(&final_dir).map_err(|e| format!("mkdir {}: {e}", final_dir.display()))?;
    copy_tree(scratch_path, &final_dir).map_err(|e| format!("copy tree: {e}"))?;
    fs::write(final_dir.join(FILE_MANIFEST), &sealed.manifest_bytes)
        .map_err(|e| format!("write manifest: {e}"))?;
    drop(scratch);

    // manifest_sha256 is the sha of `meta.json` bytes on disk. Recompute
    // it here so the JSON pointer the shell consumes carries the same
    // value the supervisor would derive at admission.
    let meta_bytes =
        fs::read(final_dir.join(FILE_MANIFEST)).map_err(|e| format!("read sealed meta: {e}"))?;
    let manifest_sha256 = sha256_hex(&meta_bytes);

    Ok(SealOutcome {
        volume_hash: sealed.volume_hash,
        volume_dir: final_dir,
        manifest_sha256,
    })
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_entry = dst.join(entry.file_name());
        if ty.is_dir() {
            fs::create_dir_all(&dst_entry)?;
            copy_tree(&entry.path(), &dst_entry)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), &dst_entry)?;
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

struct SealOutcome {
    volume_hash: String,
    volume_dir: PathBuf,
    manifest_sha256: String,
}

fn write_seal_pointer(out_json: &Path, sealed: &SealOutcome) -> Result<(), String> {
    let payload = serde_json::json!({
        "volume_hash": sealed.volume_hash,
        "volume_dir": sealed.volume_dir,
        "manifest_sha256": sealed.manifest_sha256,
    });
    fs::write(out_json, serde_json::to_vec_pretty(&payload).unwrap())
        .map_err(|e| format!("write {}: {e}", out_json.display()))?;
    Ok(())
}

/// Run `apply_install_gate(...)` against the named volume. Exits 0
/// when the gate accepts, 1 when it rejects. Shell composes with
/// `if cmd; then ACCEPTED; else REJECTED; fi`.
fn gate_check(rest: &[String]) -> Result<ExitCode, String> {
    let cache_root = PathBuf::from(parse_kv(rest, "cache-root")?);
    let volume_hash = parse_kv(rest, "volume-hash")?.to_string();
    let gate_str = parse_kv(rest, "gate")?;
    let gate = match gate_str {
        "prod" => GateLevel::Prod,
        "dev" => GateLevel::Dev,
        other => return Err(format!("--gate must be prod|dev, got {other}")),
    };
    let volume_dir = cache_root.join(&volume_hash);
    if !volume_dir.is_dir() {
        return Err(format!(
            "no sealed volume at {} — did seal-clean / seal-with-high-cve run first?",
            volume_dir.display()
        ));
    }
    // Synthesize an `InstallResult` referring to the on-disk volume.
    // The gate only inspects `volume_dir`'s sidecars; the other
    // fields are diagnostic-only and we fill them with the recomputed
    // manifest sha so the gate's error messages aren't lying.
    let meta_bytes =
        fs::read(volume_dir.join(FILE_MANIFEST)).map_err(|e| format!("read manifest: {e}"))?;
    let result = InstallResult {
        volume_hash: volume_hash.clone(),
        manifest_sha256: sha256_hex(&meta_bytes),
        cache_hit: true,
        volume_dir: volume_dir.clone(),
        lockfile_sha256: "0".repeat(64),
    };
    match apply_install_gate(&result, gate) {
        Ok(()) => {
            println!("gate accepted volume {volume_hash} under {gate_str}");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("gate REJECTED volume {volume_hash} under {gate_str}: {e}");
            Ok(ExitCode::from(1))
        }
    }
}
