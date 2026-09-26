//! Advance `crates/mvm-core/images.lock` to a verified image-set root.
//!
//! The pin-update workflow verifies the candidate root's keyless signature and
//! then calls this to rewrite the lock. The rewrite edits values in place so the
//! file's comments survive, and then re-reads the result through the same
//! parser every consumer uses: a section or key this code failed to update is a
//! refusal here, not a lock that quietly pins two different releases.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    ImageSetManifest, ImageSetRole, ImageTrainLock, MemberArtifact, MemberTarget,
};
use mvm_core::packs::Sha256Hex;

const LOCK: &str = "crates/mvm-core/images.lock";
const ARCHITECTURES: [GuestArch; 2] = [GuestArch::Aarch64, GuestArch::X86_64];

pub(crate) fn run(args: &[String]) -> Result<()> {
    let [manifest] = args else {
        bail!("usage: repin-image-lock <verified image-set.json>");
    };
    let bytes = fs::read(manifest).with_context(|| format!("cannot read {manifest}"))?;
    let lock = fs::read_to_string(LOCK).with_context(|| format!("cannot read {LOCK}"))?;
    let updated = repin(&lock, &bytes)?;
    if updated == lock {
        println!("{LOCK} already pins this root");
        return Ok(());
    }
    fs::write(Path::new(LOCK), updated).with_context(|| format!("cannot write {LOCK}"))?;
    println!("{LOCK} advanced");
    Ok(())
}

/// The values a root pins, taken from the root and nowhere else.
struct Pin {
    release_tag: String,
    manifest_sha256: Sha256Hex,
    guest_agent_protocol: (u32, u32),
    builder_cache_contract: u32,
    /// Absent when the root predates the field, and then absent from the lock
    /// too: the lock copies what the root declares, and does not invent a 0.
    builder_boot_abi: Option<u32>,
    stage0: Vec<(GuestArch, MemberArtifact)>,
}

impl Pin {
    fn from_root(bytes: &[u8]) -> Result<Self> {
        let manifest: ImageSetManifest =
            serde_json::from_slice(bytes).context("the candidate is not an image-set manifest")?;
        let Some(release) = manifest.producer.release() else {
            bail!("the candidate root was not produced by a release");
        };
        let stage0 = ARCHITECTURES
            .into_iter()
            .map(|arch| Ok((arch, stage0_artifact(&manifest, arch)?)))
            .collect::<Result<Vec<_>>>()?;
        let protocol = manifest.compatibility.guest_agent_protocol;
        Ok(Self {
            release_tag: release.release_tag.as_str().to_string(),
            manifest_sha256: Sha256Hex::from_bytes(bytes),
            guest_agent_protocol: (protocol.min(), protocol.max()),
            builder_cache_contract: manifest.compatibility.builder_cache_contract,
            builder_boot_abi: manifest.compatibility.builder_boot_abi.map(|abi| abi.get()),
            stage0,
        })
    }
}

fn stage0_artifact(manifest: &ImageSetManifest, arch: GuestArch) -> Result<MemberArtifact> {
    let member = manifest
        .members
        .iter()
        .find(|member| {
            member.role == ImageSetRole::Stage0BootstrapKernel
                && member.target == MemberTarget::Arch(arch)
        })
        .with_context(|| format!("the candidate root has no {arch} Stage 0 kernel"))?;
    match member.artifacts.as_slice() {
        [artifact] => Ok(artifact.clone()),
        _ => bail!("the {arch} Stage 0 kernel member must carry exactly one artifact"),
    }
}

/// Rewrite `lock` to pin the root in `bytes`, refusing a result the lock
/// parser would not read back as exactly that pin.
fn repin(lock: &str, bytes: &[u8]) -> Result<String> {
    let pin = Pin::from_root(bytes)?;
    let tag = quoted(&pin.release_tag);
    let mut text = lock.to_string();
    for (section, key, value) in [
        ("image_set", "release_tag", tag.clone()),
        (
            "image_set",
            "manifest_sha256",
            quoted(pin.manifest_sha256.as_str()),
        ),
        (
            "image_set.signing_identity",
            "tag_ref",
            quoted(&format!("refs/tags/{}", pin.release_tag)),
        ),
        (
            "compatibility",
            "guest_agent_protocol",
            format!(
                "{{ min = {}, max = {} }}",
                pin.guest_agent_protocol.0, pin.guest_agent_protocol.1
            ),
        ),
        (
            "compatibility",
            "builder_cache_contract",
            pin.builder_cache_contract.to_string(),
        ),
        ("boot_image", "release_tag", tag.clone()),
        ("stage0_kernel", "release_tag", tag.clone()),
    ] {
        text = set_value(&text, section, key, &value)?;
    }
    text = set_optional_value(
        &text,
        "compatibility",
        "builder_boot_abi",
        "builder_cache_contract",
        pin.builder_boot_abi.map(|abi| abi.to_string()),
    )?;
    for (arch, artifact) in &pin.stage0 {
        let section = format!("stage0_kernel.artifact.{arch}");
        text = set_value(&text, &section, "name", &quoted(artifact.name.as_str()))?;
        text = set_value(&text, &section, "sha256", &quoted(artifact.sha256.as_str()))?;
    }
    check_reads_back(&text, &pin)?;
    Ok(text)
}

fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

/// Replace `key`'s value inside `[section]`, leaving every other line —
/// comments included — untouched. Exactly one assignment must exist.
fn set_value(text: &str, section: &str, key: &str, value: &str) -> Result<String> {
    let header = format!("[{section}]");
    let mut in_section = false;
    let mut replaced = 0;
    let mut out = Vec::new();
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == header;
        } else if in_section && assigns(trimmed, key) {
            let newline = if line.ends_with('\n') { "\n" } else { "" };
            out.push(format!("{key} = {value}{newline}"));
            replaced += 1;
            continue;
        }
        out.push(line.to_string());
    }
    match replaced {
        1 => Ok(out.concat()),
        0 => bail!("{LOCK} has no `{key}` under [{section}]"),
        _ => bail!("{LOCK} assigns `{key}` more than once under [{section}]"),
    }
}

/// Set an optional `key` inside `[section]`: replace it when present, insert
/// it after `after_key` when absent, and remove it when `value` is `None`.
fn set_optional_value(
    text: &str,
    section: &str,
    key: &str,
    after_key: &str,
    value: Option<String>,
) -> Result<String> {
    let header = format!("[{section}]");
    let present = section_assigns(text, &header, key);
    match (value, present) {
        (Some(value), true) => set_value(text, section, key, &value),
        (Some(value), false) => {
            let mut in_section = false;
            let mut inserted = false;
            let mut out = Vec::new();
            for line in text.split_inclusive('\n') {
                let trimmed = line.trim();
                if trimmed.starts_with('[') {
                    in_section = trimmed == header;
                }
                out.push(line.to_string());
                if in_section && !inserted && assigns(trimmed, after_key) {
                    out.push(format!("{key} = {value}\n"));
                    inserted = true;
                }
            }
            if !inserted {
                bail!("{LOCK} has no `{after_key}` under [{section}] to place `{key}` after");
            }
            Ok(out.concat())
        }
        (None, true) => {
            let mut in_section = false;
            Ok(text
                .split_inclusive('\n')
                .filter(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with('[') {
                        in_section = trimmed == header;
                    }
                    !(in_section && assigns(trimmed, key))
                })
                .collect())
        }
        (None, false) => Ok(text.to_string()),
    }
}

fn section_assigns(text: &str, header: &str, key: &str) -> bool {
    let mut in_section = false;
    text.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == header;
        }
        in_section && assigns(trimmed, key)
    })
}

fn assigns(line: &str, key: &str) -> bool {
    line.strip_prefix(key)
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

fn check_reads_back(text: &str, pin: &Pin) -> Result<()> {
    let lock = ImageTrainLock::parse(text).context("the rewritten lock does not parse")?;
    if lock.image_set.release_tag.as_str() != pin.release_tag
        || lock.image_set.manifest_sha256 != pin.manifest_sha256
    {
        bail!("the rewritten lock does not pin the candidate root");
    }
    let protocol = lock.compatibility.guest_agent_protocol;
    if (protocol.min(), protocol.max()) != pin.guest_agent_protocol
        || lock.compatibility.builder_cache_contract != pin.builder_cache_contract
        || lock.compatibility.builder_boot_abi.map(|abi| abi.get()) != pin.builder_boot_abi
    {
        bail!("the rewritten lock does not carry the candidate's compatibility");
    }
    for (arch, artifact) in &pin.stage0 {
        let pinned = lock.stage0_kernel.for_arch(*arch)?;
        if pinned.name != artifact.name || pinned.sha256 != artifact.sha256 {
            bail!("the rewritten lock does not pin the candidate's {arch} Stage 0 kernel");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn checked_in_lock() -> String {
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(LOCK))
            .expect("read the checked-in lock")
    }

    fn stage0_member(arch: &str, name: &str, sha: &str) -> serde_json::Value {
        json!({
            "role": "stage0_bootstrap_kernel",
            "target": {"arch": arch},
            "boot_protocol": "linux_direct",
            "artifacts": [{"name": name, "format": {"kernel": "elf"}, "sha256": sha, "size": 1}],
            "required_capabilities": [],
        })
    }

    /// A root with the published shape: its Stage 0 members, and one
    /// architecture-independent member whose `target` is a bare string.
    fn root(tag: &str, stage0: [(&str, &str, &str); 2]) -> Vec<u8> {
        root_with_abi(tag, stage0, None)
    }

    fn root_with_abi(
        tag: &str,
        stage0: [(&str, &str, &str); 2],
        builder_boot_abi: Option<u32>,
    ) -> Vec<u8> {
        let mut members = stage0
            .iter()
            .map(|(arch, name, sha)| stage0_member(arch, name, sha))
            .collect::<Vec<_>>();
        members.push(json!({
            "role": "qemu_wasm_smoke_pack",
            "target": "arch_independent",
            "artifacts": [{"name": "qemu-wasm-smoke-pack.tar.gz", "format": "ext4", "sha256": "a".repeat(64), "size": 1}],
            "required_capabilities": [],
        }));
        serde_json::to_vec(&json!({
            "schema_version": 2,
            "set_version": tag.trim_start_matches("image-set/v"),
            "issued_at": "2026-09-23T00:01:56Z",
            "producer": {
                "repository": "tinylabscom/mvm-images",
                "workflow": ".github/workflows/release.yml",
                "release_tag": tag,
                "source_commit": "1b08fbc104d0a3e0ac9dd9d74ec5db3c38ff3f38"
            },
            "mvm_source_commit": "fa6d5c1b271382684f9387eed61850c299e1ade5",
            "compatibility": compatibility(builder_boot_abi),
            "nix_inputs": {"flake_locks": [], "source_revisions": []},
            "members": members,
        }))
        .expect("serialize root")
    }

    fn compatibility(builder_boot_abi: Option<u32>) -> serde_json::Value {
        let mut compatibility =
            json!({"guest_agent_protocol": {"min": 2, "max": 3}, "builder_cache_contract": 5});
        if let Some(abi) = builder_boot_abi {
            compatibility["builder_boot_abi"] = json!(abi);
        }
        compatibility
    }

    fn stage0_pins() -> [(&'static str, &'static str, String); 2] {
        [
            ("aarch64", "stage0-vmlinux-aarch64", "1".repeat(64)),
            ("x86_64", "stage0-vmlinux-x86_64", "2".repeat(64)),
        ]
    }

    /// A root declaring the builder boot ABI carries it into the lock; a later
    /// root without it takes it back out rather than leaving a stale value.
    #[test]
    fn the_builder_boot_abi_follows_the_root() {
        let pins = stage0_pins();
        let pins = [
            (pins[0].0, pins[0].1, pins[0].2.as_str()),
            (pins[1].0, pins[1].1, pins[1].2.as_str()),
        ];
        let with_abi = root_with_abi("image-set/v0.2.0", pins, Some(1));
        let text = repin(&checked_in_lock(), &with_abi).expect("repin with an ABI");
        let lock = ImageTrainLock::parse(&text).unwrap();
        assert_eq!(
            lock.compatibility.builder_boot_abi.map(|abi| abi.get()),
            Some(1)
        );
        assert_eq!(repin(&text, &with_abi).unwrap(), text, "idempotent");

        let without = root_with_abi("image-set/v0.3.0", pins, None);
        let text = repin(&text, &without).expect("repin without an ABI");
        let lock = ImageTrainLock::parse(&text).unwrap();
        assert_eq!(lock.compatibility.builder_boot_abi, None);
        assert!(!text.contains("builder_boot_abi"), "{text}");
    }

    fn next_root() -> Vec<u8> {
        root(
            "image-set/v0.2.0",
            [
                ("aarch64", "stage0-vmlinux-aarch64", &"1".repeat(64)),
                ("x86_64", "stage0-vmlinux-x86_64", &"2".repeat(64)),
            ],
        )
    }

    #[test]
    fn a_new_root_advances_every_route_consistently() {
        let bytes = next_root();

        let text = repin(&checked_in_lock(), &bytes).expect("a complete root must repin");
        let lock = ImageTrainLock::parse(&text).expect("the result parses");

        assert_eq!(lock.image_set.release_tag.as_str(), "image-set/v0.2.0");
        assert_eq!(lock.boot_image.release_tag.as_str(), "image-set/v0.2.0");
        assert_eq!(lock.stage0_kernel.release_tag.as_str(), "image-set/v0.2.0");
        assert_eq!(
            lock.image_set.manifest_sha256,
            Sha256Hex::from_bytes(&bytes)
        );
        assert_eq!(
            lock.stage0_kernel
                .for_arch(GuestArch::X86_64)
                .unwrap()
                .sha256
                .as_str(),
            "2".repeat(64)
        );
        assert_eq!(lock.compatibility.builder_cache_contract, 5);
    }

    #[test]
    fn the_rewrite_keeps_the_lock_comments_and_legacy_entry() {
        let original = checked_in_lock();

        let text = repin(&original, &next_root()).unwrap();

        let comments = |text: &str| {
            text.lines()
                .filter(|line| line.trim_start().starts_with('#'))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(comments(&text), comments(&original));
        let before = ImageTrainLock::parse(&original).unwrap();
        let after = ImageTrainLock::parse(&text).unwrap();
        assert_eq!(
            after.legacy, before.legacy,
            "the legacy entry is not a pin to advance"
        );
    }

    #[test]
    fn repinning_to_the_current_root_changes_nothing() {
        let original = checked_in_lock();
        let once = repin(&original, &next_root()).unwrap();

        let twice = repin(&once, &next_root()).unwrap();

        assert_eq!(once, twice);
    }

    #[test]
    fn a_root_without_a_stage0_kernel_is_refused() {
        let mut value: serde_json::Value = serde_json::from_slice(&next_root()).unwrap();
        value["members"].as_array_mut().unwrap().remove(1);
        let bytes = serde_json::to_vec(&value).unwrap();

        let error = repin(&checked_in_lock(), &bytes).expect_err("must refuse");

        assert!(
            format!("{error:#}").contains("x86_64 Stage 0 kernel"),
            "{error:#}"
        );
    }

    #[test]
    fn a_lock_missing_a_section_the_root_pins_is_refused() {
        let lock = checked_in_lock().replace("[stage0_kernel.artifact.aarch64]", "[elsewhere]");

        let error = repin(&lock, &next_root()).expect_err("must refuse");

        assert!(
            format!("{error:#}").contains("under [stage0_kernel.artifact.aarch64]"),
            "{error:#}"
        );
    }

    #[test]
    fn set_value_touches_only_the_named_section() {
        let text = "[a]\nrelease_tag = \"x\"\n\n[b]\nrelease_tag = \"x\"\n";

        let out = set_value(text, "b", "release_tag", "\"y\"").unwrap();

        assert_eq!(
            out,
            "[a]\nrelease_tag = \"x\"\n\n[b]\nrelease_tag = \"y\"\n"
        );
    }
}
