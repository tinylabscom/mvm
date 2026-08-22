use super::*;
use crate::commands::shared::{self, VolumeSpec};
#[cfg(test)]
use crate::commands::vm::host_signer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartReceiptInput {
    pub(super) machine_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) deployment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) resolved_digest: Option<String>,
    pub(super) cpus: u32,
    pub(super) memory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) mem_initial: Option<String>,
    pub(super) profile: String,
    pub(super) network_posture: String,
    pub(super) egress_enforcement: String,
    pub(super) volumes: Vec<MachineStartVolumePolicy>,
    pub(super) init: MachineStartInitPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartVolumePolicy {
    pub(super) kind: String,
    pub(super) host_path_sha256: String,
    pub(super) guest_path: String,
    pub(super) read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartInitPolicy {
    pub(super) command_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) script_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartJsonSummary {
    pub(super) schema_version: u32,
    pub(super) invocation: MachineStartReceiptInput,
    pub(super) outcome: MachineStartReceiptOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) receipt_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartPreflightSummary {
    pub(super) schema_version: u32,
    pub(super) dry_run: bool,
    pub(super) will_execute: bool,
    pub(super) machine: MachineStartPreflightMachine,
    pub(super) invocation: MachineStartReceiptInput,
    pub(super) resources: MachineStartPreflightResources,
    pub(super) receipt: MachineStartPreflightReceipt,
    pub(super) notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartPreflightMachine {
    pub(super) name: String,
    pub(super) image_reference_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) resolved_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartPreflightResources {
    pub(super) cpus: u32,
    pub(super) memory: String,
    pub(super) memory_mib: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) mem_initial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) mem_initial_mib: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartPreflightReceipt {
    pub(super) requested: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) path_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::commands::machine) struct MachineStartReceiptPayload {
    pub(super) schema_version: u32,
    pub(super) receipt_id: String,
    pub(super) recorded_at: String,
    pub(super) invocation: MachineStartReceiptInput,
    pub(super) outcome: MachineStartReceiptOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MachineStartReceiptOutcome {
    pub(super) resolved_digest: String,
    pub(super) started_at: String,
    pub(super) init_commands_executed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::commands::machine) struct SignedMachineStartReceipt {
    pub(super) payload: MachineStartReceiptPayload,
    pub(super) signature: MachineStartReceiptSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::commands::machine) struct MachineStartReceiptSignature {
    pub(super) algorithm: String,
    pub(super) signer_id: String,
    pub(super) public_key_sha256: String,
    pub(super) signature_base64: String,
}

impl MachineStartJsonSummary {
    pub(super) fn from_parts(
        invocation: MachineStartReceiptInput,
        outcome: MachineStartReceiptOutcome,
        receipt_path: Option<PathBuf>,
    ) -> Self {
        Self {
            schema_version: 1,
            invocation,
            outcome,
            receipt_path,
        }
    }
}

pub(super) fn machine_start_init_policy(spec: &MachineSpec) -> MachineStartInitPolicy {
    let script_sha256 =
        (!spec.init.is_empty()).then(|| sha256_hex(spec.init.join("\n").as_bytes()));
    MachineStartInitPolicy {
        command_count: spec.init.len(),
        script_sha256,
    }
}

pub(super) fn machine_start_volume_policy(
    spec: &MachineSpec,
) -> Result<Vec<MachineStartVolumePolicy>> {
    let mut volumes = Vec::with_capacity(spec.volumes.len());
    for volume in &spec.volumes {
        let parsed = shared::parse_volume_spec(volume)?;
        let (kind, host_path, guest_path, read_only) = match parsed {
            VolumeSpec::DirShare {
                host_dir,
                guest_mount,
                read_only,
            } => ("dir_share", host_dir, guest_mount, read_only),
            VolumeSpec::Disk {
                host,
                guest,
                read_only,
                ..
            } => ("disk", host, guest, read_only),
        };
        volumes.push(MachineStartVolumePolicy {
            kind: kind.to_string(),
            host_path_sha256: sha256_hex(host_path.as_bytes()),
            guest_path,
            read_only,
        });
    }
    Ok(volumes)
}

pub(super) fn machine_start_receipt_input(
    spec: &MachineSpec,
    backend: &str,
) -> Result<MachineStartReceiptInput> {
    let network_policy =
        shared::resolve_run_network_policy(spec.net, &spec.allow_host)?.with_ai(spec.ai.clone());
    crate::exec::validate_image_egress_backend_name(
        backend,
        spec.image.is_some(),
        &network_policy,
    )?;
    let _ = validate_machine_memory(&spec.memory, spec.mem_initial.as_deref())?;
    let volumes = machine_start_volume_policy(spec)?;
    Ok(MachineStartReceiptInput {
        machine_name: spec.name.clone(),
        image: spec.image.clone(),
        manifest: spec.manifest.clone(),
        deployment: spec.deployment.clone(),
        resolved_digest: spec.resolved_digest.clone(),
        cpus: spec.cpus,
        memory: spec.memory.clone(),
        mem_initial: spec.mem_initial.clone(),
        profile: spec.profile.clone(),
        network_posture: network_policy.posture_label(),
        egress_enforcement: shared::egress_enforcement_label(backend, &network_policy),
        volumes,
        init: machine_start_init_policy(spec),
    })
}

pub(super) fn machine_start_volume_summary(volumes: &[MachineStartVolumePolicy]) -> &'static str {
    if volumes.is_empty() {
        "none"
    } else if volumes.iter().all(|volume| volume.read_only) {
        "ro-only"
    } else {
        "contains-rw"
    }
}

pub(super) fn machine_start_preflight_summary(
    spec: &MachineSpec,
    backend_override: Option<&str>,
    receipt: Option<&Path>,
) -> Result<MachineStartPreflightSummary> {
    let backend = backend_override
        .map(str::to_owned)
        .unwrap_or_else(|| shared::resolve_effective_hypervisor("firecracker"));
    let invocation = machine_start_receipt_input(spec, &backend)?;
    let (memory_mib, mem_initial_mib) =
        validate_machine_memory(&spec.memory, spec.mem_initial.as_deref())?;
    let mut notes = vec![
        "preflight only; no image was resolved, pulled, booted, or executed".to_string(),
        "raw host paths are intentionally omitted from policy output".to_string(),
    ];
    if receipt.is_some() {
        notes.push("receipt path is hashed, but no receipt is written during dry-run".to_string());
    }
    Ok(MachineStartPreflightSummary {
        schema_version: 1,
        dry_run: true,
        will_execute: false,
        machine: MachineStartPreflightMachine {
            name: spec.name.clone(),
            image_reference_sha256: sha256_hex(
                spec.image
                    .as_deref()
                    .or(spec.manifest.as_deref())
                    .unwrap_or("")
                    .as_bytes(),
            ),
            resolved_digest: spec.resolved_digest.clone(),
        },
        invocation,
        resources: MachineStartPreflightResources {
            cpus: spec.cpus,
            memory: spec.memory.clone(),
            memory_mib,
            mem_initial: spec.mem_initial.clone(),
            mem_initial_mib,
        },
        receipt: MachineStartPreflightReceipt {
            requested: receipt.is_some(),
            path_sha256: receipt.map(|path| sha256_hex(path.to_string_lossy().as_bytes())),
        },
        notes,
    })
}

pub(super) fn print_machine_start_preflight_human(summary: &MachineStartPreflightSummary) {
    println!("mvmctl machine start dry-run: no VM will be booted");
    println!("machine: {}", summary.machine.name);
    println!(
        "image: OCI reference sha256={}{}",
        summary.machine.image_reference_sha256,
        summary
            .machine
            .resolved_digest
            .as_deref()
            .map(|digest| format!(" last_resolved_digest={digest}"))
            .unwrap_or_default()
    );
    println!(
        "resources: cpus={} memory={} ({} MiB)",
        summary.resources.cpus, summary.resources.memory, summary.resources.memory_mib
    );
    if let Some(mem_initial) = summary.resources.mem_initial.as_deref() {
        let mem_initial_mib = summary.resources.mem_initial_mib.unwrap_or_default();
        println!("mem-initial: {mem_initial} ({mem_initial_mib} MiB)");
    }
    println!("profile: {}", summary.invocation.profile);
    println!("network: {}", summary.invocation.network_posture);
    println!("enforced: {}", summary.invocation.egress_enforcement);
    if summary.invocation.init.command_count == 0 {
        println!("dev.init: none");
    } else {
        println!(
            "dev.init: {} command(s) script_sha256={}",
            summary.invocation.init.command_count,
            summary
                .invocation
                .init
                .script_sha256
                .as_deref()
                .unwrap_or("missing")
        );
    }
    if summary.invocation.volumes.is_empty() {
        println!("host shares: none");
    } else {
        println!("host shares:");
        for volume in &summary.invocation.volumes {
            println!(
                "  kind={} host_sha256={} -> {} ({})",
                volume.kind,
                volume.host_path_sha256,
                volume.guest_path,
                if volume.read_only { "ro" } else { "rw" }
            );
        }
    }
    if summary.receipt.requested {
        if let Some(path_sha256) = &summary.receipt.path_sha256 {
            println!("receipt: requested path_sha256={path_sha256} (not written in dry-run)");
        } else {
            println!("receipt: requested (not written in dry-run)");
        }
    }
}

pub(super) fn write_machine_start_receipt(
    path: &Path,
    invocation: MachineStartReceiptInput,
    outcome: MachineStartReceiptOutcome,
) -> Result<()> {
    let payload = MachineStartReceiptPayload {
        schema_version: 1,
        receipt_id: uuid::Uuid::new_v4().to_string(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
        invocation,
        outcome,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).context("serializing machine-start receipt payload")?;
    let signer = load_or_init().context("loading host signer for machine-start receipt")?;
    let signature = signer.signing.sign(&payload_bytes);
    let public_key = signer.verifying.to_bytes();
    let receipt = SignedMachineStartReceipt {
        payload,
        signature: MachineStartReceiptSignature {
            algorithm: "ed25519".to_string(),
            signer_id: host_signer_id(),
            public_key_sha256: sha256_hex(&public_key),
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        },
    };

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating receipt directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(&receipt).context("serializing machine-start receipt")?;
    std::fs::write(path, bytes)
        .with_context(|| format!("writing machine-start receipt {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_machine_start_receipt(
    path: &Path,
    pubkey_path: Option<&Path>,
) -> Result<SignedMachineStartReceipt> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading machine-start receipt {}", path.display()))?;
    let receipt: SignedMachineStartReceipt = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing machine-start receipt {}", path.display()))?;
    if receipt.payload.schema_version != 1 {
        anyhow::bail!(
            "unsupported machine-start receipt schema_version {}; this build supports 1",
            receipt.payload.schema_version
        );
    }
    if !receipt.signature.algorithm.eq_ignore_ascii_case("ed25519") {
        anyhow::bail!(
            "unsupported machine-start receipt signature algorithm '{}'",
            receipt.signature.algorithm
        );
    }
    let verifying = load_machine_start_receipt_pubkey(pubkey_path)?;
    let public_key = verifying.to_bytes();
    let actual_key_hash = sha256_hex(&public_key);
    if actual_key_hash != receipt.signature.public_key_sha256 {
        anyhow::bail!(
            "machine-start receipt public key hash mismatch: receipt={}, supplied={actual_key_hash}",
            receipt.signature.public_key_sha256
        );
    }
    let payload_bytes = serde_json::to_vec(&receipt.payload)
        .context("serializing machine-start receipt payload for verify")?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature.signature_base64)
        .context("decoding machine-start receipt signature")?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "machine-start receipt signature is {} bytes; expected 64",
            sig_bytes.len()
        )
    })?;
    let signature = Signature::from_bytes(&sig_arr);
    verifying
        .verify(&payload_bytes, &signature)
        .context("verifying machine-start receipt signature")?;
    Ok(receipt)
}

#[cfg(test)]
pub(super) fn load_machine_start_receipt_pubkey(
    pubkey_path: Option<&Path>,
) -> Result<VerifyingKey> {
    let path = match pubkey_path {
        Some(path) => path.to_path_buf(),
        None => host_signer::default_keys_dir()?.join(PUBLIC_FILENAME),
    };
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading machine-start receipt pubkey {}", path.display()))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "receipt pubkey {} is {} bytes; expected 32",
            path.display(),
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&arr).context("parsing machine-start receipt pubkey")
}
