//! Inspect an installed workload pack only after re-verifying its lock pin,
//! publisher signature, and complete payload.

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use mvm_core::packs::Sha256Hex;
use mvm_core::registry_pack::{
    AuthenticatedRegistryManifest, PackReference, VerifiedRegistryApplication,
    VerifiedRegistryManifest,
};
use mvm_core::registry_pack_store::{
    load_pack_lockfile, load_publisher_policy_or_official_default, open_installed_registry_manifest,
};

#[derive(Serialize)]
struct VerifiedPackInfo {
    reference: String,
    description: String,
    manifest_sha256: String,
    signer_identity: String,
    signer_issuer: String,
    official_status: &'static str,
    revocation_scope: &'static str,
    revocation_required: bool,
    publisher_issuer: String,
    accepted_signing_identities: Vec<String>,
    policy_files: Vec<String>,
    policy_documents: Vec<VerifiedPolicy>,
    image_manifest: Option<String>,
    files: Vec<VerifiedFile>,
}

#[derive(Serialize)]
struct VerifiedPolicy {
    path: String,
    text: String,
}

#[derive(Serialize)]
struct VerifiedFile {
    path: String,
    sha256: String,
    size: u64,
}

pub(super) fn run(reference_arg: &str, json: bool, verify_only: bool) -> Result<()> {
    let reference: PackReference = crate::pack_registry::parse_user_reference(reference_arg)?;
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path())?;
    let publisher = load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?;
    let (installed, verified) = open_installed_registry_manifest(
        &mvm_core::config::registry_pack_cache_dir(),
        &lock,
        &publisher.policy,
        &reference,
    )?;
    let verified = match verified {
        VerifiedRegistryManifest::Legacy(pack) => pack,
        VerifiedRegistryManifest::Application(application) => {
            return inspect_application(&application, json, verify_only);
        }
        VerifiedRegistryManifest::RuntimeLayer(_) => {
            anyhow::bail!("runtime layer inspection requires verified archive custody");
        }
    };
    let manifest = verified.manifest();
    let revocation_required = manifest.reference.namespace() == "mvm"
        || matches!(
            &manifest.image,
            Some(mvm_core::registry_pack::RegistryPackImage::Built(_))
        );
    let official = manifest.reference.namespace() == "mvm";
    let trust = publisher
        .policy
        .trust_for_namespace(manifest.reference.namespace())?;
    let mut policy_documents = Vec::new();
    for file in manifest
        .files
        .iter()
        .filter(|file| matches!(file.path.as_str(), "pack/group.toml" | "pack/profile.toml"))
    {
        let path = installed.payload_root().join(&file.path);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading signed pack policy {}", file.path))?;
        ensure!(
            u64::try_from(bytes.len()).context("pack policy exceeds supported file size")?
                == file.size,
            "pack policy size changed: {}",
            file.path
        );
        ensure!(
            Sha256Hex::from_bytes(&bytes) == file.sha256,
            "pack policy digest changed: {}",
            file.path
        );
        let text = String::from_utf8(bytes)
            .with_context(|| format!("pack policy is not UTF-8: {}", file.path))?;
        policy_documents.push(VerifiedPolicy {
            path: file.path.clone(),
            text,
        });
    }
    let info = VerifiedPackInfo {
        reference: manifest.reference.to_string(),
        description: manifest.description.clone(),
        manifest_sha256: verified.manifest_sha256().as_str().to_string(),
        signer_identity: verified.signer().identity.clone(),
        signer_issuer: verified.signer().issuer.clone(),
        official_status: if official {
            "established"
        } else {
            "not_established"
        },
        revocation_scope: if official {
            "mvm_release_identity"
        } else {
            "operator_configured_only"
        },
        revocation_required,
        publisher_issuer: trust.issuer,
        accepted_signing_identities: trust.accepted_identities,
        policy_files: policy_documents
            .iter()
            .map(|policy| policy.path.clone())
            .collect(),
        policy_documents,
        image_manifest: manifest.image.as_ref().and_then(|image| match image {
            mvm_core::registry_pack::RegistryPackImage::Source(source) => {
                Some(source.manifest.clone())
            }
            mvm_core::registry_pack::RegistryPackImage::Built(_) => None,
        }),
        files: manifest
            .files
            .iter()
            .map(|file| VerifiedFile {
                path: file.path.clone(),
                sha256: file.sha256.as_str().to_string(),
                size: file.size,
            })
            .collect(),
    };

    if json {
        return crate::json_out::emit_json(&info);
    }
    if verify_only {
        println!(
            "Verified {} ({})",
            safe(&info.reference),
            safe(&info.manifest_sha256)
        );
        println!("Signer identity: {}", safe(&info.signer_identity));
        println!("Signer issuer: {}", safe(&info.signer_issuer));
        for line in trust_status_lines(official, revocation_required) {
            println!("{line}");
        }
        println!("Signature proves publisher identity and integrity, not safety.");
        return Ok(());
    }
    println!("Pack: {}", safe(&info.reference));
    println!("Description: {}", safe(&info.description));
    println!("Manifest SHA-256: {}", safe(&info.manifest_sha256));
    println!("Signer identity: {}", safe(&info.signer_identity));
    println!("Signer issuer: {}", safe(&info.signer_issuer));
    for line in trust_status_lines(official, revocation_required) {
        println!("{line}");
    }
    println!("Publisher issuer: {}", safe(&info.publisher_issuer));
    println!(
        "Accepted signing identities: {}",
        safe_join(&info.accepted_signing_identities)
    );
    println!("Policy files: {}", safe_join(&info.policy_files));
    for policy in &info.policy_documents {
        println!(
            "Policy {}: {}",
            safe(&policy.path),
            serde_json::to_string(&policy.text)?
        );
    }
    if let Some(image) = &info.image_manifest {
        println!("Image source manifest: {}", safe(image));
    }
    println!("Payload files: {}", info.files.len());
    for file in &info.files {
        println!(
            "  {}  {}  {} bytes",
            safe(file.sha256.as_str()),
            safe(&file.path),
            file.size
        );
    }
    println!("Signature proves publisher identity and integrity, not safety.");
    Ok(())
}

#[derive(Serialize)]
struct ApplicationInfo {
    kind: &'static str,
    reference: String,
    description: String,
    manifest_sha256: String,
    signer_identity: String,
    signer_issuer: String,
    guest_arch: String,
    bundle: mvm_core::registry_pack::application::RegistryApplicationBundle,
    verification_scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_manifest: Option<mvm_core::plan::bundle::BundleManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    launch: Option<LaunchSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch_warning: Option<String>,
}

/// What the signed bundle says the application runs and may do, lifted from
/// its manifest so `pack info` answers it without a second command.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct LaunchSummary {
    entrypoint: Vec<String>,
    working_dir: Option<String>,
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    egress_allowed: Option<bool>,
    allow_hosts: Vec<String>,
}

fn launch_summary(manifest: &mvm_core::plan::bundle::BundleManifest) -> Option<LaunchSummary> {
    let environment = manifest.environment()?;
    let resources = manifest.resources.as_ref();
    Some(LaunchSummary {
        entrypoint: environment.entrypoint.argv.clone(),
        working_dir: environment.entrypoint.working_dir.clone(),
        vcpus: resources.map(|r| r.vcpus),
        mem_mib: resources.map(|r| r.mem_mib),
        egress_allowed: manifest.security_posture().map(|p| p.allows_egress),
        allow_hosts: environment
            .policy
            .as_ref()
            .map(|policy| policy.allow_hosts.clone())
            .unwrap_or_default(),
    })
}

fn application_info(
    manifest: &mvm_core::registry_pack::application::RegistryApplicationManifest,
    manifest_sha256: &Sha256Hex,
    signer: &mvm_core::crypto::image_verify::VerifiedSigner,
) -> ApplicationInfo {
    ApplicationInfo {
        kind: "application",
        reference: manifest.reference.to_string(),
        description: manifest.description.clone(),
        manifest_sha256: manifest_sha256.as_str().to_owned(),
        signer_identity: signer.identity.clone(),
        signer_issuer: signer.issuer.clone(),
        guest_arch: manifest.application.guest_arch.clone(),
        bundle: manifest.application.bundle.clone(),
        verification_scope: "descriptor_and_bundle_archive",
        bundle_manifest: None,
        launch: None,
        arch_warning: crate::pack_registry::arch_mismatch_warning(
            &manifest.reference.to_string(),
            &manifest.application.guest_arch,
            mvm_build::builder_vm::host_arch_tag(),
        ),
    }
}

fn inspect_application(
    application: &VerifiedRegistryApplication,
    json: bool,
    verify_only: bool,
) -> Result<()> {
    use mvm_core::plan::bundle::{BundleRegistry, FsTrustStore};
    use mvm_core::registry_pack::application_bundle::verify_application_bundle;

    let registry = BundleRegistry::default_path()?;
    let trust = FsTrustStore::default_path()?;
    let archive = registry.archive_path(
        application
            .manifest()
            .application
            .bundle
            .archive_sha256
            .as_str(),
    );
    // A descriptor is not proof that the archive exists or its independent
    // author is trusted. Keep the existing archive verifier as that boundary.
    let verified_archive =
        verify_application_bundle(application, &archive, &trust).with_context(|| {
            format!(
                "reverifying local application bundle for {}; \
                 use `mvmctl pull {}` to acquire a missing archive",
                application.reference(),
                application.reference(),
            )
        })?;
    let mut info = application_info(
        application.manifest(),
        application.manifest_sha256(),
        application.signer(),
    );
    info.launch = launch_summary(&verified_archive.bundle().manifest);
    info.bundle_manifest = Some(verified_archive.bundle().manifest.clone());
    if json {
        return crate::json_out::emit_json(&info);
    }
    if verify_only {
        println!(
            "Verified application descriptor and bundle archive: {} ({})",
            safe(&info.reference),
            safe(&info.manifest_sha256)
        );
    } else {
        println!("Application: {}", safe(&info.reference));
        println!("Description: {}", safe(&info.description));
        println!("Manifest SHA-256: {}", safe(&info.manifest_sha256));
    }
    println!("Signer identity: {}", safe(&info.signer_identity));
    println!("Signer issuer: {}", safe(&info.signer_issuer));
    for line in trust_status_lines(application.reference().namespace() == "mvm", false) {
        println!("{line}");
    }
    println!("Guest architecture: {}", safe(&info.guest_arch));
    println!(
        "Bundle archive SHA-256: {}",
        safe(info.bundle.archive_sha256.as_str())
    );
    println!("Bundle archive size: {} bytes", info.bundle.archive_size);
    println!("Bundle author key: {}", safe(&info.bundle.key_id.0));
    if let Some(launch) = &info.launch {
        for line in launch_lines(launch) {
            println!("{line}");
        }
    }
    if let Some(warning) = &info.arch_warning {
        crate::ui::warn(&safe(warning));
    }
    println!(
        "Verification covers the descriptor and archive, not extracted-file custody or launch admission."
    );
    Ok(())
}

/// Neutralize terminal control characters (ESC, CR, newline, C1 and the
/// rest) in a publisher-supplied string, which a signature does not make safe
/// to print raw.
pub(crate) fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn safe_join(items: &[String]) -> String {
    items
        .iter()
        .map(|item| safe(item))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Text lines for the launch summary; each argv element is quoted separately.
fn launch_lines(launch: &LaunchSummary) -> Vec<String> {
    let argv: Vec<String> = launch
        .entrypoint
        .iter()
        .map(|arg| format!("\"{}\"", safe(arg)))
        .collect();
    let mut lines = vec![format!("Entrypoint: {}", argv.join(" "))];
    if let Some(dir) = &launch.working_dir {
        lines.push(format!("Working directory: {}", safe(dir)));
    }
    if let (Some(vcpus), Some(mem)) = (launch.vcpus, launch.mem_mib) {
        lines.push(format!("Resources: {vcpus} vCPU, {mem} MiB"));
    }
    match launch.egress_allowed {
        Some(true) => lines.push(format!(
            "Policy: egress allowed to [{}]",
            safe_join(&launch.allow_hosts)
        )),
        Some(false) => lines.push("Policy: no network egress".to_owned()),
        None => {}
    }
    lines
}

/// Human-readable trust status. `official` is only passed after the pack and
/// the official revocation feed have both verified.
fn trust_status_lines(official: bool, revocation_required: bool) -> [&'static str; 2] {
    match (official, revocation_required) {
        (true, _) => [
            "Official status: verified MVM release",
            "Revocation scope: MVM-controlled signed release feed",
        ],
        (false, true) => [
            "Official status: not established by this verification",
            "Revocation scope: independent operator trust and a fresh signed feed required",
        ],
        (false, false) => [
            "Official status: not established by this verification",
            "Revocation scope: operator-configured signed feed only; no feed is required",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::{LaunchSummary, application_info, launch_lines, safe, trust_status_lines};

    const HOSTILE: &str = "a\x1b[2Jb\rc\nd\u{9b}e";

    fn assert_no_control(text: &str) {
        assert!(
            !text.chars().any(char::is_control),
            "raw control in {text:?}"
        );
    }

    #[test]
    fn safe_escapes_every_control_character() {
        let out = safe(HOSTILE);
        assert_no_control(&out);
        assert!(out.contains("\\u{1b}") && out.contains("\\r") && out.contains("\\n"));
        assert!(out.contains("\\u{9b}"));
    }

    #[test]
    fn hostile_launch_fields_never_print_a_control_character() {
        let launch = LaunchSummary {
            entrypoint: vec![HOSTILE.into(), "ok".into()],
            working_dir: Some(HOSTILE.into()),
            vcpus: Some(1),
            mem_mib: Some(128),
            egress_allowed: Some(true),
            allow_hosts: vec![HOSTILE.into()],
        };
        let lines = launch_lines(&launch);
        assert_eq!(lines.len(), 4);
        for line in &lines {
            assert_no_control(line);
        }
    }

    #[test]
    fn application_info_keeps_descriptor_and_bundle_identities_distinct() {
        // Formatting data only: no synthetic publisher or bundle authority.
        let manifest = mvm_core::registry_pack::application::parse_application_manifest(
            &serde_json::to_vec(&serde_json::json!({
                "schema_version": 2,
                "kind": "application",
                "reference": "runtime/python@1.2.3",
                "description": "Application info unit fixture",
                "application": {
                    "schema_version": 1,
                    "guest_arch": "x86_64",
                    "bundle": {
                        "source": "https://example.test/python.mvmpkg",
                        "archive_sha256": "a".repeat(64),
                        "archive_size": 42,
                        "key_id": "b".repeat(32)
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let digest = mvm_core::packs::Sha256Hex::new("c".repeat(64)).unwrap();
        let signer = mvm_core::crypto::image_verify::VerifiedSigner {
            identity: "unit-formatting-identity".to_owned(),
            issuer: "unit-formatting-issuer".to_owned(),
        };
        let info = serde_json::to_value(application_info(&manifest, &digest, &signer)).unwrap();
        assert_eq!(info["kind"], "application");
        assert_eq!(info["reference"], "runtime/python@1.2.3");
        assert_eq!(info["manifest_sha256"], "c".repeat(64));
        assert_eq!(info["bundle"]["archive_sha256"], "a".repeat(64));
        assert_eq!(info["bundle"]["key_id"], "b".repeat(32));
        assert_eq!(info["guest_arch"], "x86_64");
        assert_eq!(info["verification_scope"], "descriptor_and_bundle_archive");
        assert!(info.get("files").is_none());
        assert!(info.get("policy_documents").is_none());
        assert!(info.get("launch_authorized").is_none());
        assert!(info.get("launch").is_none());
    }

    #[test]
    fn launch_summary_is_absent_without_an_environment_member() {
        let manifest = mvm_core::plan::bundle::BundleManifest {
            schema_version: 5,
            publisher: "p".into(),
            key_id: mvm_core::plan::bundle::KeyId("b".repeat(32)),
            arch: "x86_64".into(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            labels: Default::default(),
            artifacts: vec![],
            members: vec![],
            verity: None,
            resources: None,
        };
        assert_eq!(super::launch_summary(&manifest), None);
    }

    #[test]
    fn only_an_official_pack_reports_the_mvm_release_feed() {
        let [status, scope] = trust_status_lines(true, true);
        assert_eq!(status, "Official status: verified MVM release");
        assert!(scope.contains("MVM-controlled"));
        for required in [true, false] {
            let [status, scope] = trust_status_lines(false, required);
            assert!(status.contains("not established"));
            assert!(!scope.contains("MVM-controlled"));
            assert_eq!(scope.contains("fresh signed feed required"), required);
        }
    }
}
