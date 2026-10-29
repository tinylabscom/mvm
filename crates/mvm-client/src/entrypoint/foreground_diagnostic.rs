//! Test-only native-client request/refusal observation, not a workflow witness.

use super::{Inputs, OwnedVm, canonical_private_directory, path_env, read_json};
use anyhow::{Context, Result, ensure};
use mvm_agentd::vsock::ExecEvent;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const BAKED_SHA: &str = "7544d5d74f38f78b7d5457728dea4bf3f467befda7c1a892021dcfbfda1ab4e1";
const VERSION: &str = "2.1.273";
const SCRIPT: &str = include_str!("foreground_diagnostic.sh");
const OUTPUT_LIMIT: usize = 512 * 1024;
const SYNTHETIC_SECRET: &str = "foreground-diagnostic-anthropic";

fn require_file_secret_backend(selection: Option<&str>) -> Result<()> {
    ensure!(
        selection == Some("file"),
        "diagnostic requires the private-home file secret backend"
    );
    Ok(())
}

fn prepared_synthetic_binding() -> Result<crate::admission::secrets::ResolvedPlanSecrets> {
    use secrecy::ExposeSecret as _;
    // Require the explicit file selector before opening any secret service;
    // unset/auto could consult the native credential store.
    require_file_secret_backend(std::env::var("MVM_SECRET_STORE_BACKEND").ok().as_deref())?;
    let store = mvm_core::crypto::secret_store::default_secret_store();
    let value = store.get("local", SYNTHETIC_SECRET)?;
    ensure!(
        value.expose_secret() == "synthetic-foreground-diagnostic-not-a-credential",
        "prepared diagnostic binding must contain only the fixed synthetic value"
    );
    let resolved = crate::admission::run_secrets::resolve_launch_secrets(
        None,
        &[SYNTHETIC_SECRET.to_owned()],
        &[],
        "local",
    )?;
    ensure!(
        resolved.secrets.len() == 1 && resolved.secrets[0].name == "ANTHROPIC_API_KEY",
        "prepared synthetic binding must resolve the signed required environment slot"
    );
    Ok(resolved)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedProvenance {
    schema: u32,
    vendor_version: String,
    vendor_signer_fingerprint: String,
    vendor_original_sha256: String,
    baked_sha256: String,
    transformation_evidence_sha256: String,
    pack_archive_sha256: String,
    pack_publisher_key_sha256: String,
    pack_publisher_key_id: String,
    diagnostic_script_sha256: String,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_provenance(bytes: &[u8], approved_digest: &str) -> Result<ApprovedProvenance> {
    ensure!(bytes.len() <= 65536, "provenance exceeds its bound");
    ensure!(
        digest(approved_digest),
        "invalid operator-approved provenance digest"
    );
    ensure!(
        hex::encode(Sha256::digest(bytes)) == approved_digest,
        "operator-approved provenance pin mismatch"
    );
    let proof: ApprovedProvenance = serde_json::from_slice(bytes)?;
    ensure!(
        proof.schema == 1
            && proof.vendor_version == VERSION
            && proof.vendor_signer_fingerprint == "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
            && proof.vendor_original_sha256
                == "0ea64e932c6fac35ce4e992140612157fe1cecab052d59539873b350a594d3c6"
            && proof.baked_sha256 == BAKED_SHA
            && digest(&proof.pack_archive_sha256)
            && digest(&proof.pack_publisher_key_sha256)
            && proof.pack_publisher_key_id.len() == 32
            && proof
                .pack_publisher_key_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && proof.diagnostic_script_sha256 == hex::encode(Sha256::digest(SCRIPT.as_bytes()))
            && digest(&proof.transformation_evidence_sha256),
        "approved provenance does not describe the expected diagnostic artifacts"
    );
    Ok(proof)
}

fn require_approved_provenance(root: &std::path::Path) -> Result<ApprovedProvenance> {
    let path = path_env("MVM_FOREGROUND_PROVENANCE_PATH")?;
    ensure!(
        path == root.join("foreground-provenance.json"),
        "provenance must be in the private fixture root"
    );
    canonical_private_directory(root)?;
    let lease = mvm_core::transcript::secure_cleanup::CaptureDirectory::for_writer(root)?;
    let bytes = lease.read_private_member("foreground-provenance.json", 65536)?;
    // This pin records the operator's evidence approval. It is not a signature
    // verifier or independent proof of the vendor-to-baked transformation.
    validate_provenance(
        &bytes,
        &std::env::var("MVM_FOREGROUND_APPROVED_PROVENANCE_SHA256")
            .context("operator-approved provenance digest required")?,
    )
}

fn signed_diagnostic_script(
    archive: &std::path::Path,
    proof: &ApprovedProvenance,
) -> Result<String> {
    use mvm_core::plan::bundle::{FsTrustStore, verify_bundle_file};
    use std::io::{Read as _, Seek as _, SeekFrom};
    const MAX_ARCHIVE: u64 = 4 * 1024 * 1024 * 1024;
    ensure!(
        std::fs::symlink_metadata(archive)?.is_file(),
        "diagnostic archive must be a regular file"
    );
    let mut snapshot = tempfile::NamedTempFile::new()?;
    let copied = std::io::copy(
        &mut std::fs::File::open(archive)?.take(MAX_ARCHIVE + 1),
        snapshot.as_file_mut(),
    )?;
    ensure!(
        copied <= MAX_ARCHIVE,
        "diagnostic archive exceeds its bound"
    );
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(snapshot.path())? == proof.pack_archive_sha256,
        "diagnostic archive approval pin mismatch"
    );
    let trust = FsTrustStore::default_path()?;
    super::canonical_private_directory(trust.root())?;
    let public_key = trust
        .root()
        .join(format!("{}.pub", proof.pack_publisher_key_id));
    ensure!(
        std::fs::symlink_metadata(&public_key)?.is_file(),
        "diagnostic publisher key must be a regular file"
    );
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(&public_key)?
            == proof.pack_publisher_key_sha256,
        "diagnostic publisher approval pin mismatch"
    );
    // Canonical verification covers the entire pack before any tar member is
    // selected. The private snapshot cannot be replaced by the source path.
    let verified = verify_bundle_file(snapshot.path(), &trust)?;
    ensure!(
        verified.key_id.0 == proof.pack_publisher_key_id,
        "diagnostic publisher identity mismatch"
    );
    let mut script = None;
    for (name, expected) in [
        (
            "foreground-diagnostic-script",
            proof.diagnostic_script_sha256.as_str(),
        ),
        (
            "foreground-vendor-provenance",
            proof.transformation_evidence_sha256.as_str(),
        ),
    ] {
        let members: Vec<_> = verified
            .manifest
            .artifacts
            .iter()
            .filter(|member| member.name == name)
            .collect();
        ensure!(
            members.len() == 1,
            "signed diagnostic member missing or ambiguous"
        );
        let member = members[0];
        ensure!(
            member.role == mvm_core::plan::bundle::ArtifactRole::Other
                && member.sha256 == expected
                && member.size_bytes <= 65536,
            "signed diagnostic member role, digest or size mismatch"
        );
        snapshot.as_file_mut().seek(SeekFrom::Start(0))?;
        let bytes = capture_member(
            snapshot.as_file_mut(),
            &member.path,
            expected,
            member.size_bytes,
        )?;
        if name == "foreground-diagnostic-script" {
            script = Some(String::from_utf8(bytes)?);
        }
    }
    script.context("signed diagnostic script missing")
}

fn capture_member(
    archive: impl std::io::Read,
    path: &str,
    expected: &str,
    expected_size: u64,
) -> Result<Vec<u8>> {
    use std::io::Read as _;
    ensure!(expected_size <= 65536, "signed member exceeds its bound");
    mvm_core::plan::bundle::ensure_safe_path(path)?;
    let mut captured = None;
    for entry in tar::Archive::new(archive).entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == std::path::Path::new(path) {
            ensure!(
                captured.is_none() && entry.header().entry_type().is_file(),
                "duplicate or nonregular signed member"
            );
            let mut bytes = Vec::new();
            entry.by_ref().take(65537).read_to_end(&mut bytes)?;
            ensure!(
                u64::try_from(bytes.len())? == expected_size
                    && hex::encode(Sha256::digest(&bytes)) == expected,
                "signed member bytes changed"
            );
            captured = Some(bytes);
        }
    }
    captured.context("verified signed member missing")
}

fn report(output: &[u8]) -> Result<serde_json::Value> {
    use base64::Engine as _;
    ensure!(
        output.len() <= OUTPUT_LIMIT,
        "diagnostic output exceeds its bound"
    );
    let text = std::str::from_utf8(output)?;
    let mut lines = text.lines();
    ensure!(
        lines.next() == Some(&format!("client_sha256={BAKED_SHA}")),
        "baked client digest evidence mismatch"
    );
    ensure!(
        lines.next() == Some("client_version=2.1.273 (Claude Code)"),
        "client version mismatch"
    );
    let exit: i32 = lines
        .next()
        .and_then(|v| v.strip_prefix("client_exit="))
        .context("client exit missing")?
        .parse()?;
    ensure!(
        exit != 0 && exit != 124 && exit != 137,
        "client did not reach a bounded refusal"
    );
    let attempts: usize = lines
        .next()
        .and_then(|v| v.strip_prefix("attempts="))
        .context("attempt count missing")?
        .parse()?;
    ensure!(
        (1..4).contains(&attempts),
        "capture limit reached or invalid attempt count; observation is incomplete"
    );
    let mut requests = Vec::new();
    for _ in 0..attempts {
        let request_line = lines
            .next()
            .and_then(|v| v.strip_prefix("request="))
            .context("request line missing")?;
        ensure!(request_line.len() <= 4096, "request line exceeds its bound");
        let request_parts: Vec<_> = request_line.split_whitespace().collect();
        ensure!(
            request_parts.len() == 3 && request_parts[2] == "HTTP/1.1",
            "invalid observed request line"
        );
        let api_version = lines
            .next()
            .and_then(|v| v.strip_prefix("api_version="))
            .context("API version evidence missing")?;
        let encoding = lines
            .next()
            .and_then(|v| v.strip_prefix("encoding="))
            .context("encoding evidence missing")?;
        let betas = lines
            .next()
            .and_then(|v| v.strip_prefix("betas="))
            .context("beta evidence missing")?;
        for value in [api_version, encoding, betas] {
            ensure!(
                value.len() <= 16384
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b",._:/+; =-".contains(&b)),
                "invalid sanitized protocol header"
            );
        }
        let headers = lines
            .next()
            .and_then(|v| v.strip_prefix("headers="))
            .context("headers missing")?;
        ensure!(
            headers.len() <= 4160
                && headers
                    .split(',')
                    .filter(|v| !v.is_empty())
                    .all(|v| v.len() <= 64
                        && v.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')),
            "invalid redacted header names"
        );
        let encoded = lines
            .next()
            .and_then(|v| v.strip_prefix("body="))
            .context("body missing")?;
        ensure!(encoded.len() <= 87384, "request body exceeds its bound");
        let body = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        ensure!(body.len() <= 65536, "request body exceeds its bound");
        let identity_encoding = encoding.is_empty() || encoding == "identity,";
        let parsed: Option<serde_json::Value> = if identity_encoding {
            serde_json::from_slice(&body).ok()
        } else {
            None
        };
        let object = parsed.as_ref().and_then(serde_json::Value::as_object);
        let shape: serde_json::Map<String, serde_json::Value> = object
            .into_iter()
            .flat_map(|v| v.iter())
            .map(|(key, value)| {
                let kind = match value {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "boolean",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                };
                (key.clone(), serde_json::json!(kind))
            })
            .collect();
        let model = object
            .and_then(|v| v.get("model"))
            .and_then(serde_json::Value::as_str)
            .filter(|v| {
                v.len() <= 128
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            });
        let max_tokens = object
            .and_then(|v| v.get("max_tokens"))
            .and_then(serde_json::Value::as_u64);
        let stream = object
            .and_then(|v| v.get("stream"))
            .and_then(serde_json::Value::as_bool);
        let tool_types: Vec<_> = object
            .and_then(|v| v.get("tools"))
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .map(|tool| {
                tool.get("type")
                    .and_then(serde_json::Value::as_str)
                    .filter(|v| {
                        v.len() <= 128
                            && v.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    })
                    .unwrap_or("custom-or-unclassified")
            })
            .collect();
        let mut findings = Vec::new();
        if request_parts[0] != "POST" {
            findings.push("unexpected-method");
        }
        if request_parts[1] != "/v1/messages" {
            findings.push("noncanonical-path-or-query");
        }
        if !betas.is_empty() {
            findings.push("beta-header-present");
        }
        if !identity_encoding {
            findings.push("unsupported-content-encoding");
        }
        if model != Some("claude-haiku-4-5-20251001") {
            findings.push("missing-or-different-model");
        }
        if !matches!(max_tokens, Some(1..=20000)) {
            findings.push("missing-or-out-of-bound-max-tokens");
        }
        if stream.is_none() {
            findings.push("stream-value-missing");
        }
        requests.push(serde_json::json!({
            "request_line": request_line, "method": request_parts[0], "path_and_query": request_parts[1],
            "http_version": request_parts[2], "api_version": api_version, "content_encoding": encoding,
            "anthropic_beta": betas, "header_names": headers, "body_shape": shape,
            "model": model, "max_tokens": max_tokens, "stream": stream, "tool_types": tool_types,
            "strict_contract_comparable": model.is_some() && max_tokens.is_some() && stream.is_some(),
            "compatibility_findings": findings,
            "body_decode_status": if !identity_encoding { "unsupported-encoding" } else if object.is_some() { "json-object" } else { "invalid-json-object" },
        }));
    }
    ensure!(lines.next().is_none(), "unexpected diagnostic output");
    Ok(serde_json::json!({
        "observation": "native-client-request-and-configured-http400-refusal",
        "workflow_success": false,
        "retry_free_claim": false,
        "wrapper_executed": false,
        "operator_approved_provenance_pin": true,
        "independent_transformation_verification": false,
        "client_sha256": BAKED_SHA, "client_version": VERSION,
        "client_exit": exit, "attempts": attempts, "requests": requests,
        "requested_controls": {
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "20000", "CLAUDE_CODE_MAX_RETRIES": "0",
            "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1", "ENABLE_TOOL_SEARCH": "false"
        },
        "requested_controls_honored_claim": false,
    }))
}

#[test]
#[ignore = "operator-approved provenance and isolated admitted native fixture required; request/refusal only"]
fn native_claude_foreground_request_refusal() -> Result<()> {
    use crate::entrypoint::{
        EntrypointAdmission, EntrypointVm, SessionVmName, WorkloadSource, resolve_slot,
    };
    let inputs = Inputs::read_for(false)?;
    let proof = require_approved_provenance(&inputs.root)?;
    let secrets = prepared_synthetic_binding()?;
    super::declare_helpers()?;
    let name = format!("foreground-{:032x}", rand::random::<u128>());
    let mut vm = OwnedVm::new(name);
    let slot = resolve_slot(WorkloadSource::Manifest(&inputs.source))?;
    ensure!(
        cfg!(feature = "manifest-verify"),
        "foreground diagnostic requires canonical artifact verification support"
    );
    let archive = mvm_runtime::vm::template::lifecycle::installed_bundle_archive(&slot)?
        .context("foreground diagnostic requires an installed signed bundle, not a raw rootfs")?;
    let signed_script = signed_diagnostic_script(&archive, &proof)?;
    let policy = EntrypointAdmission::builder("hvf")
        .dev(true)
        .cpus(1)
        .mem_mib(4096)
        .secrets(secrets)
        .build()?;
    vm.owner = Some(crate::entrypoint::call::boot_entrypoint_vm_owned(
        EntrypointVm {
            slot: &slot,
            vm_name: SessionVmName::Exact(&vm.name),
            cpus: 1,
            memory_mib: 4096,
            admission: policy,
            portable_boot_assets: None,
        },
        None,
    )?);
    let observed = (|| {
        let owner = vm.owner.as_mut().context("original owner missing")?;
        let admitted_bundle = owner
            .resources()
            .admission
            .admitted
            .plan()
            .bundle
            .as_ref()
            .context("diagnostic boot did not retain a signed bundle pin")?;
        ensure!(
            admitted_bundle.bundle_sha256 == proof.pack_archive_sha256
                && admitted_bundle.key_id.0 == proof.pack_publisher_key_id,
            "original-owner admission differs from the verified diagnostic pack"
        );
        ensure!(
            owner.resources().config.volumes.is_empty()
                && owner.resources().config.secret_files.is_empty(),
            "diagnostic must not mount host data or secrets"
        );
        let cfg: mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig =
            read_json(&mvm_core::config::vm_state_dir(&vm.name).join("supervisor.json"))?;
        ensure!(
            cfg.kernel.canonicalize()? == inputs.kernel,
            "unexpected workload kernel"
        );
        let mut stdout = Vec::new();
        let mut overflow = false;
        let terminal = owner.with_original(|_, runtime| {
            runtime.validate_live()?;
            runtime.exec(
                "/nix/store/7ls7m3jyp74xb0ahnybm2pk4s2pvnk3n-bash-5.3p3/bin/bash -s",
                Some(signed_script),
                Some(120),
                |event| {
                    if let ExecEvent::Stdout { chunk } = event {
                        if stdout.len().saturating_add(chunk.len()) <= OUTPUT_LIMIT {
                            stdout.extend_from_slice(chunk);
                        } else {
                            overflow = true;
                        }
                    }
                },
            )
        })?;
        ensure!(
            matches!(terminal, ExecEvent::Exit { code: 0 }),
            "foreground diagnostic script failed or timed out"
        );
        ensure!(!overflow, "foreground diagnostic output overflow");
        report(&stdout)
    })();
    // Stop is attempted even on verification/transport/report failure. A stop
    // error prevents cleanup and leaves the original owner in this wrapper.
    vm.stop()?;
    let report = observed?;
    eprintln!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[test]
fn secret_backend_gate_refuses_native_and_automatic_selection() {
    require_file_secret_backend(Some("file")).unwrap();
    for selection in [None, Some("auto"), Some("keyring"), Some("FILE"), Some("")] {
        assert!(require_file_secret_backend(selection).is_err());
    }
}

#[test]
fn approved_provenance_accepts_only_the_pinned_candidate() {
    let mut proof = serde_json::json!({
        "schema": 1,
        "vendor_version": VERSION,
        "vendor_signer_fingerprint": "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE",
        "vendor_original_sha256": "0ea64e932c6fac35ce4e992140612157fe1cecab052d59539873b350a594d3c6",
        "baked_sha256": BAKED_SHA,
        "transformation_evidence_sha256": "a52c645c9cc15e7d2af88a71fc2caa24f6cf2d7d90e77d72db95d765ecfc375b",
        "pack_archive_sha256": "cdbd8005dc356add632b3fce4ae19b7912e509df2d359e1d3b8786252de1a2b1",
        "pack_publisher_key_sha256": "ada32b29ba81aa751cd16a3735be29e933fb4f86bdf50f009d2aff143a9e2f51",
        "pack_publisher_key_id": "a".repeat(32),
        "diagnostic_script_sha256": hex::encode(Sha256::digest(SCRIPT.as_bytes())),
    });
    let check = |proof: &serde_json::Value| {
        let bytes = serde_json::to_vec(proof).unwrap();
        validate_provenance(&bytes, &hex::encode(Sha256::digest(&bytes)))
    };
    check(&proof).unwrap();
    for key in [
        "vendor_original_sha256",
        "baked_sha256",
        "diagnostic_script_sha256",
    ] {
        let mut changed = proof.clone();
        changed[key] = serde_json::json!("0".repeat(64));
        assert!(check(&changed).is_err());
    }
    proof["unexpected"] = serde_json::json!(true);
    assert!(check(&proof).is_err());
}

#[test]
fn selected_member_capture_is_bounded_and_digest_checked() {
    let build = |copies: usize| {
        let mut tar = tar::Builder::new(Vec::new());
        for _ in 0..copies {
            let mut header = tar::Header::new_gnu();
            header.set_size(3);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, "artifacts/diagnostic.sh", &b"abc"[..])
                .unwrap();
        }
        tar.into_inner().unwrap()
    };
    let archive = build(1);
    let sha = hex::encode(Sha256::digest(b"abc"));
    assert_eq!(
        capture_member(&archive[..], "artifacts/diagnostic.sh", &sha, 3).unwrap(),
        b"abc"
    );
    assert!(capture_member(&archive[..], "artifacts/diagnostic.sh", &"0".repeat(64), 3).is_err());
    assert!(capture_member(&archive[..], "artifacts/diagnostic.sh", &sha, 4).is_err());
    assert!(capture_member(&archive[..], "artifacts/diagnostic.sh", &sha, 65537).is_err());
    assert!(capture_member(&archive[..], "../diagnostic.sh", &sha, 3).is_err());
    assert!(capture_member(&archive[..], "missing.sh", &sha, 3).is_err());
    assert!(capture_member(&build(2)[..], "artifacts/diagnostic.sh", &sha, 3).is_err());
}

#[test]
fn provenance_pin_rejects_missing_approval_and_wrong_bytes() {
    assert!(validate_provenance(b"{}", "").is_err());
    assert!(validate_provenance(b"{}", &"0".repeat(64)).is_err());
    assert!(validate_provenance(&vec![0; 65537], &"0".repeat(64)).is_err());
}

#[test]
fn report_redacts_values_and_counts_every_attempt() {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD
        .encode(br#"{"model":"claude-haiku-4-5-20251001","max_tokens":20000,"messages":[{"content":"synthetic-prompt"}],"stream":true,"tools":[{"type":"web_search_20250305"}]}"#);
    let record = format!(
        "request=POST /v1/messages HTTP/1.1\napi_version=2023-06-01,\nencoding=\nbetas=\nheaders=x-api-key,content-length,\nbody={body}\n"
    );
    let output = format!(
        "client_sha256={BAKED_SHA}\nclient_version=2.1.273 (Claude Code)\nclient_exit=1\nattempts=2\n{record}{record}"
    );
    let value = report(output.as_bytes()).unwrap();
    assert_eq!(value["attempts"], 2);
    assert!(!value.to_string().contains("synthetic-prompt"));
    assert_eq!(value["requests"][0]["body_shape"]["messages"], "array");
    assert_eq!(value["requests"][0]["model"], "claude-haiku-4-5-20251001");
    assert_eq!(value["requests"][0]["max_tokens"], 20000);
    assert_eq!(value["requests"][0]["stream"], true);
    assert_eq!(value["requests"][0]["tool_types"][0], "web_search_20250305");
    let beta = report(
        output
            .replace("/v1/messages HTTP", "/v1/messages?beta=true HTTP")
            .replace("betas=\n", "betas=synthetic-beta,\n")
            .as_bytes(),
    )
    .unwrap();
    assert!(
        beta["requests"][0]["compatibility_findings"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("beta-header-present"))
    );
    assert_eq!(
        beta["requests"][0]["path_and_query"],
        "/v1/messages?beta=true"
    );
    let encoded = report(output.replace("encoding=\n", "encoding=gzip,\n").as_bytes()).unwrap();
    assert_eq!(encoded["requests"][0]["strict_contract_comparable"], false);
    assert_eq!(
        encoded["requests"][0]["body_decode_status"],
        "unsupported-encoding"
    );
    let saturated = output.replace("attempts=2", "attempts=4");
    assert!(
        report(saturated.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("observation is incomplete")
    );
    assert!(report(output.replace("attempts=2", "attempts=1").as_bytes()).is_err());
    assert!(
        report(
            output
                .replace("client_exit=1", "client_exit=124")
                .as_bytes()
        )
        .is_err()
    );
}

#[test]
fn http_handler_accepts_bounded_length_and_refuses_ambiguous_framing() {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    let handler = SCRIPT
        .split_once("<<'HANDLER'\n")
        .unwrap()
        .1
        .split_once("\nHANDLER\n")
        .unwrap()
        .0;
    let run = |request: &[u8]| {
        let directory = tempfile::tempdir().unwrap();
        let tools = directory.path().join("tools");
        // Host standard utilities exercise framing only, not guest BusyBox.
        std::fs::write(&tools, "#!/bin/sh\nexec \"$@\"\n").unwrap();
        std::fs::set_permissions(&tools, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("handler");
        std::fs::write(&path, handler).unwrap();
        let mut child = Command::new("/bin/bash")
            .arg(path)
            .env("B", tools)
            .env("work", directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(request).unwrap();
        let output = child.wait_with_output().unwrap();
        let complete = directory.path().join("complete-1").exists();
        let protocol = std::fs::read_to_string(directory.path().join("protocol-1")).ok();
        (output, complete, protocol)
    };
    let request = |headers: &str, body: &str| {
        format!(
            "POST /v1/messages HTTP/1.1\r\nx-api-key: synthetic-foreground-diagnostic-not-a-credential\r\n{headers}\r\n{body}"
        )
    };
    let (output, complete, _) = run(request("Content-Length: 2\r\n", "{}").as_bytes());
    assert!(output.status.success());
    assert!(complete);
    assert!(output.stdout.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    let beta_request = request("Content-Length: 2\r\nAnthropic-Beta: synthetic-beta\r\nAnthropic-Version: 2023-06-01\r\nContent-Encoding: gzip\r\n", "{}")
        .replace("/v1/messages HTTP", "/v1/messages?beta=true HTTP");
    let (output, complete, protocol) = run(beta_request.as_bytes());
    assert!(output.status.success() && complete);
    let protocol = protocol.unwrap();
    assert!(protocol.contains("request=POST /v1/messages?beta=true HTTP/1.1"));
    assert!(protocol.contains("betas=synthetic-beta,"));
    assert!(protocol.contains("api_version=2023-06-01,"));
    assert!(protocol.contains("encoding=gzip,"));
    for invalid in [
        request("Content-Length: 2\r\nContent-Length: 2\r\n", "{}"),
        request("Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", "{}"),
        request("Content-Length: 2\r\nExpect: 100-continue\r\n", "{}"),
        request("Content-Length: 65537\r\n", "{}"),
        request("Content-Length: -1\r\n", "{}"),
        request("Content-Length: 3\r\n", "{}"),
        request("", "{}"),
    ] {
        let (output, complete, _) = run(invalid.as_bytes());
        assert!(!output.status.success());
        assert!(!complete);
        assert!(output.stdout.is_empty());
    }
}
