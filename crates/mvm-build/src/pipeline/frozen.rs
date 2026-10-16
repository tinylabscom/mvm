//! Owned, checked inputs for builds that must not substitute contributor sources.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// A private source snapshot. Its owner must outlive every consumer of its path.
#[derive(Debug)]
pub struct FrozenInputs {
    staging: tempfile::TempDir,
    digest: String,
    observation: Option<(String, PathBuf)>,
}

impl FrozenInputs {
    /// Copy through the builder's actual disk-input staging filter, then verify
    /// that neither concurrent mutation nor filtering changed the compiled tree.
    pub fn stage(source: &Path, expected: &str) -> Result<Self> {
        if tree_digest(source)? != expected {
            bail!("compiled artifact changed before frozen staging");
        }
        let staging = crate::builder_vm_runtime::stage_filtered_work_input(source)
            .map_err(anyhow::Error::new)?;
        let inputs = Self {
            staging,
            digest: expected.to_string(),
            observation: None,
        };
        inputs.verify()?;
        Ok(inputs)
    }

    pub fn path(&self) -> &Path {
        self.staging.path()
    }

    /// Explicit diagnostic opt-in. Destination must be invocation-private;
    /// callers publish it only after the entire operation succeeds.
    pub fn with_input_observation(mut self, revision: &str, destination: PathBuf) -> Result<Self> {
        if revision.len() != 40 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("input observation requires an exact 40-digit mvm revision");
        }
        self.observation = Some((revision.to_string(), destination));
        Ok(self)
    }

    pub(crate) fn observation(&self) -> Option<(&str, &Path)> {
        self.observation
            .as_ref()
            .map(|(rev, path)| (rev.as_str(), path.as_path()))
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    pub fn verify(&self) -> Result<()> {
        if tree_digest(self.path())? != self.digest {
            bail!("frozen build input changed at the builder staging boundary");
        }
        Ok(())
    }
}

/// Digest regular files' relative paths, modes and bytes in sorted order.
/// Symlinks contribute their target rather than the target's contents.
pub fn tree_digest(root: &Path) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let mut entries = Vec::new();
    collect(root, root, &mut entries)?;
    entries.sort();
    let mut hasher = Sha256::new();
    for relative in entries {
        let path = root.join(&relative);
        let metadata = std::fs::symlink_metadata(&path)?;
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        if metadata.file_type().is_symlink() {
            hasher.update(b"link:");
            hasher.update(std::fs::read_link(&path)?.to_string_lossy().as_bytes());
        } else {
            hasher.update(format!("{:o}:", metadata.permissions().mode() & 0o777).as_bytes());
            hasher.update(std::fs::read(&path)?);
        }
        hasher.update([0]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        let kind = std::fs::symlink_metadata(&path)?.file_type();
        if kind.is_dir() {
            collect(root, &path, out)?;
        } else {
            out.push(path.strip_prefix(root)?.to_path_buf());
        }
    }
    Ok(())
}

/// Diagnostic evidence is intentionally separate from admission and signing.
pub const INPUT_OBSERVATION_MAX_BYTES: u64 = 1024 * 1024;

fn observed_output_members() -> impl Iterator<Item = &'static str> {
    [
        "vmlinux",
        "rootfs.ext4",
        crate::builder_vm::SIDECAR_FILENAME,
    ]
    .into_iter()
    .chain(crate::builder_output::NIX_OUTPUT_MEMBERS.iter().copied())
}

pub(crate) fn observation_script(digest: &str, revision: &str, job: &str) -> (String, String) {
    use crate::builder_vm_runtime::shell_single_quote_escape;
    let before = r#"
OBS_DIR=$(mktemp -d /tmp/mvm-input-observation.XXXXXX)
trap 'rm -rf "$OBS_DIR"' EXIT
OBS_INPUT='@DIGEST@'
OBS_REV='@REVISION@'
OBS_JOB='@JOB@'
OBS_CMD_SHA=$(sha256sum "$0" | cut -d ' ' -f1)
OBS_FLAKE_SHA=$(sha256sum "$FLAKE_REF/flake.nix" | cut -d ' ' -f1)
# Bound the producer as well as the host reader. No source tree is exported.
if [ "$("$NIX_BIN" --version)" != "nix (Nix) 2.31.5" ]; then
    echo "input observation requires Nix 2.31.5; unsupported builder Nix version" >&2
    exit 1
fi
(ulimit -f 1024; "$NIX_BIN" flake metadata "$FLAKE_REF" --json --no-write-lock-file --impure > "$OBS_DIR/metadata.json")
test "$(wc -c < "$OBS_DIR/metadata.json")" -le 524288
jq -e '.locks | select(.version == 7 and (.root | type == "string") and (.nodes | type == "object"))' "$OBS_DIR/metadata.json" > "$OBS_DIR/flake.lock"
test "$(wc -c < "$OBS_DIR/flake.lock")" -le 524288
# Resolve the root input edge, never a guessed node called mvm. This narrow
# diagnostic refuses follows edges rather than guessing their resolution.
if ! jq -e --arg rev "$OBS_REV" '
  def valid_hash: if type == "string" then test("^sha256-[A-Za-z0-9+/]{43}=$") else false end;
  . as $l | .nodes[.root].inputs.mvm as $edge |
  ($edge | type == "string") and
  ($edge != $l.root) and
  ($l.nodes[$edge].locked.type == "github") and
  ($l.nodes[$edge].locked.owner == "tinylabscom") and
  ($l.nodes[$edge].locked.repo == "mvm") and
  ($l.nodes[$edge].locked.dir == "nix") and
  ($l.nodes[$edge].locked.rev == $rev) and
  ($l.nodes[$edge].locked | has("ref") | not) and
  ($l.nodes[$edge].locked.narHash | valid_hash) and
  ([.nodes | to_entries[] | select(.key != $l.root) |
    if .value.locked.type == "path" then
      (.key == $l.nodes[$edge].inputs["mvm-workspace"]) and
      (.value.flake == false) and
      (.value.locked == {"type":"path","path":".."}) and
      (.value.parent == ["mvm"]) and
      (.value | has("inputs") | not)
    else
      (.value.locked.narHash | valid_hash) and (.value | has("parent") | not)
    end] | all)
' "$OBS_DIR/flake.lock" > /dev/null; then
    echo "input observation refuses mismatched mvm pin, follows edge, malformed narHash or unbound relative node; only the inherited mvm nix/.. workspace is supported" >&2
    exit 1
fi
chmod 0400 "$OBS_DIR/flake.lock"
OBS_LOCK_SHA=$(sha256sum "$OBS_DIR/flake.lock" | cut -d ' ' -f1)
"#.replace("@DIGEST@", &shell_single_quote_escape(digest))
        .replace("@REVISION@", &shell_single_quote_escape(revision))
        .replace("@JOB@", &shell_single_quote_escape(job));
    let after = r#"
# Emit only after the real build and member copy succeeded.
test "$OBS_LOCK_SHA" = "$(sha256sum "$OBS_DIR/flake.lock" | cut -d ' ' -f1)"
test "$OBS_CMD_SHA" = "$(sha256sum "$0" | cut -d ' ' -f1)"
test "$OBS_FLAKE_SHA" = "$(sha256sum "$FLAKE_REF/flake.nix" | cut -d ' ' -f1)"
OBS_META_SHA=$(sha256sum "$OBS_DIR/metadata.json" | cut -d ' ' -f1)
test -f /out/vmlinux
test -f /out/rootfs.ext4
for name in @MEMBERS@; do
    if [ -f "/out/$name" ]; then
        jq -n --arg name "$name" --arg digest "$(sha256sum "/out/$name" | cut -d ' ' -f1)" \
            '{($name):$digest}' > "$OBS_DIR/output-$name.json"
    fi
done
jq -s add "$OBS_DIR"/output-*.json > "$OBS_DIR/outputs.json"
jq -n --rawfile raw "$OBS_DIR/metadata.json" --rawfile rawlock "$OBS_DIR/flake.lock" \
  --slurpfile outputs "$OBS_DIR/outputs.json" \
  --arg input "$OBS_INPUT" --arg rev "$OBS_REV" --arg ref "$FLAKE_REF" \
  --arg attr "$ATTR_PATH" --arg out "$NIX_OUT" --arg lock "$OBS_LOCK_SHA" \
  --arg meta "$OBS_META_SHA" --arg cmd "$OBS_CMD_SHA" --arg flake "$OBS_FLAKE_SHA" \
  --arg job "$OBS_JOB" \
  '{format:"mvm-frozen-input-observation/v1", graph_binding:"reference-lock-file",
    output_stage:"builder-produced-before-host-sealing", output_sha256:$outputs[0],
    input_sha256:$input, expected_mvm_revision:$rev, flake_ref:$ref, attr_path:$attr,
    store_path:$out, lock_sha256:$lock, metadata_sha256:$meta, cmd_sha256:$cmd,
    flake_sha256:$flake, job_id:$job, raw_metadata:$raw, raw_lock:$rawlock}' > "$OBS_DIR/report.json"
test "$(wc -c < "$OBS_DIR/report.json")" -le 1048576
cp "$OBS_DIR/report.json" /out/frozen-input-observation.json
sync
"#.replace("@MEMBERS@", &observed_output_members().collect::<Vec<_>>().join(" "));
    (before, after)
}

/// Consume transport-only evidence before its staging directory becomes a
/// reusable artifact cache. The checked bytes remain invocation-owned.
pub(crate) fn take_input_observation(
    path: &Path,
    digest: &str,
    revision: &str,
    output_hash: &str,
) -> Result<Vec<u8>> {
    let bytes = read_input_observation(path, digest, revision, output_hash)?;
    std::fs::remove_file(path).context("removing transport-only input observation")?;
    Ok(bytes)
}

pub(crate) fn read_input_observation(
    path: &Path,
    digest: &str,
    revision: &str,
    output_hash: &str,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > INPUT_OBSERVATION_MAX_BYTES {
        bail!("input observation is not a bounded regular file");
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(INPUT_OBSERVATION_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > INPUT_OBSERVATION_MAX_BYTES {
        bail!("oversized input observation");
    }
    let report: serde_json::Value = serde_json::from_slice(&bytes)?;
    for (key, expected) in [
        ("format", "mvm-frozen-input-observation/v1"),
        ("graph_binding", "reference-lock-file"),
        ("output_stage", "builder-produced-before-host-sealing"),
        ("input_sha256", digest),
        ("expected_mvm_revision", revision),
        ("flake_ref", "/work"),
    ] {
        if report[key].as_str() != Some(expected) {
            bail!("input observation mismatch: {key}");
        }
    }
    let out = report["store_path"]
        .as_str()
        .context("missing observed store path")?;
    let expected_prefix = format!("/nix/store/{output_hash}-");
    if !out.starts_with(&expected_prefix) || out.contains('\n') || out[11..].contains('/') {
        bail!("input observation does not match returned build result");
    }
    let raw = report["raw_metadata"]
        .as_str()
        .context("missing raw flake metadata")?;
    let hash = |s: &[u8]| {
        Sha256::digest(s)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    if raw.len() > 524288
        || report["metadata_sha256"].as_str() != Some(hash(raw.as_bytes()).as_str())
    {
        bail!("input observation metadata digest mismatch");
    }
    let meta: serde_json::Value = serde_json::from_str(raw)?;
    let locks = &meta["locks"];
    let raw_lock = report["raw_lock"]
        .as_str()
        .context("missing consuming lock bytes")?;
    let consuming: serde_json::Value = serde_json::from_str(raw_lock)?;
    if raw_lock.len() > 524288
        || &consuming != locks
        || report["lock_sha256"].as_str() != Some(hash(raw_lock.as_bytes()).as_str())
    {
        bail!("consuming lock differs from captured metadata graph");
    }
    let root = locks["root"].as_str().context("missing lock root")?;
    let edge = locks["nodes"][root]["inputs"]["mvm"]
        .as_str()
        .context("missing direct mvm root edge")?;
    let locked = &locks["nodes"][edge]["locked"];
    if locks["version"] != 7
        || edge == root
        || locked["type"] != "github"
        || locked["owner"] != "tinylabscom"
        || locked["repo"] != "mvm"
        || locked["dir"] != "nix"
        || locked["rev"].as_str() != Some(revision)
        || locked.get("ref").is_some()
    {
        bail!("input observation mvm graph revision mismatch");
    }
    for (name, node) in locks["nodes"].as_object().context("missing lock nodes")? {
        if name != root {
            // The non-flake workspace inherits the selected mvm repository's
            // content identity: dir=nix and path=.. resolves to that source's
            // root, not outside it. No other relative path shape is supported.
            if node["locked"]["type"] == "path" {
                if locks["nodes"][edge]["inputs"]["mvm-workspace"].as_str() != Some(name)
                    || node["flake"] != false
                    || node["locked"] != serde_json::json!({"type":"path","path":".."})
                    || node["parent"] != serde_json::json!(["mvm"])
                    || node.get("inputs").is_some()
                {
                    bail!("unbound relative graph node");
                }
                continue;
            }
            if node.get("parent").is_some() {
                bail!("unexpected graph node parent");
            }
            let nar = node["locked"]["narHash"]
                .as_str()
                .context("unlocked graph node")?;
            if !nar.starts_with("sha256-")
                || nar.len() != 51
                || !nar.ends_with('=')
                || !nar.as_bytes()[7..50]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
            {
                bail!("malformed graph narHash");
            }
        }
    }
    for key in ["cmd_sha256", "flake_sha256", "lock_sha256"] {
        let value = report[key].as_str().context("missing observation digest")?;
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("malformed input observation digest");
        }
    }
    if report["job_id"].as_str().is_none_or(str::is_empty)
        || report["attr_path"].as_str().is_none_or(str::is_empty)
    {
        bail!("missing observation job identity");
    }
    let outputs = report["output_sha256"]
        .as_object()
        .context("missing observed output hashes")?;
    for required in ["vmlinux", "rootfs.ext4"] {
        if !outputs.contains_key(required) {
            bail!("missing observed output member: {required}");
        }
    }
    for (name, value) in outputs {
        let hash = value.as_str().context("malformed observed output digest")?;
        if !observed_output_members().any(|member| member == name)
            || hash.len() != 64
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("malformed observed output member: {name}");
        }
    }
    Ok(bytes)
}

pub(crate) fn verify_observed_outputs(dir: &Path, report: &serde_json::Value) -> Result<()> {
    for name in observed_output_members() {
        let member = crate::builder_output::regular_member_if_present(&dir.join(name))?;
        let expected = report["output_sha256"][name].as_str();
        match (member, expected) {
            (Some(path), Some(expected)) => {
                if mvm_core::crypto::image_verify::sha256_file(&path)? != expected {
                    bail!("observed builder-produced output digest mismatch: {name}");
                }
            }
            (None, None) => {}
            _ => bail!("observed builder-produced output member mismatch: {name}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation_fixture(revision: &str) -> serde_json::Value {
        let lock = serde_json::json!({
            "version":7, "root":"actual-root", "nodes":{
                "actual-root":{"inputs":{"mvm":"chosen-edge"}},
                "chosen-edge":{"locked":{"type":"github","owner":"tinylabscom","repo":"mvm","dir":"nix",
                    "rev":revision,"narHash":format!("sha256-{}=", "A".repeat(43))}}
            }
        });
        let raw = serde_json::json!({"locks":lock}).to_string();
        let raw_lock = lock.to_string();
        let hash = |s: &str| {
            Sha256::digest(s.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        serde_json::json!({
            "format":"mvm-frozen-input-observation/v1", "graph_binding":"reference-lock-file",
            "output_stage":"builder-produced-before-host-sealing",
            "output_sha256":{"vmlinux":"a".repeat(64),"rootfs.ext4":"b".repeat(64)},
            "input_sha256":"source-digest","expected_mvm_revision":revision,"flake_ref":"/work",
            "attr_path":"packages.aarch64-linux.default", "store_path":"/nix/store/output-result",
            "raw_metadata":raw,"metadata_sha256":hash(&raw), "raw_lock":raw_lock,
            "lock_sha256":hash(&raw_lock), "cmd_sha256":"a".repeat(64),
            "flake_sha256":"b".repeat(64), "job_id":"unique-job"
        })
    }

    fn bind_fixture_graph(report: &mut serde_json::Value, locks: &serde_json::Value) {
        let raw = serde_json::json!({"locks":locks}).to_string();
        let raw_lock = locks.to_string();
        let hash = |s: &str| {
            Sha256::digest(s.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        report["raw_metadata"] = serde_json::json!(raw);
        report["metadata_sha256"] = serde_json::json!(hash(&raw));
        report["raw_lock"] = serde_json::json!(raw_lock);
        report["lock_sha256"] = serde_json::json!(hash(&raw_lock));
    }

    #[test]
    fn non_native_output_bytes_refuse_stale_cache_missing_and_mismatched_members() {
        let produced = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        for dir in [produced.path(), cache.path()] {
            std::fs::write(dir.join("vmlinux"), b"kernel").unwrap();
            std::fs::write(dir.join("rootfs.ext4"), b"rootfs").unwrap();
        }
        let mut report = observation_fixture(&"a".repeat(40));
        for member in ["vmlinux", "rootfs.ext4"] {
            report["output_sha256"][member] = serde_json::json!(
                mvm_core::crypto::image_verify::sha256_file(&produced.path().join(member)).unwrap()
            );
        }
        verify_observed_outputs(produced.path(), &report).unwrap();
        verify_observed_outputs(cache.path(), &report).unwrap();
        // Store-path identity is unchanged; the selected cache bytes are not.
        std::fs::write(cache.path().join("rootfs.ext4"), b"stale").unwrap();
        assert!(verify_observed_outputs(cache.path(), &report).is_err());
        std::fs::remove_file(produced.path().join("vmlinux")).unwrap();
        assert!(verify_observed_outputs(produced.path(), &report).is_err());
        std::fs::write(produced.path().join("vmlinux"), b"kernel").unwrap();
        report["output_sha256"]["vmlinux"] = serde_json::json!("0".repeat(64));
        assert!(verify_observed_outputs(produced.path(), &report).is_err());
        report["output_sha256"]["vmlinux"] = serde_json::json!(
            mvm_core::crypto::image_verify::sha256_file(&produced.path().join("vmlinux")).unwrap()
        );
        std::fs::write(produced.path().join("initrd"), b"unobserved-initrd").unwrap();
        assert!(verify_observed_outputs(produced.path(), &report).is_err());
    }

    #[test]
    fn non_native_inherited_workspace_is_bound_to_exact_parent_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report");
        let revision = "a".repeat(40);
        let mut report = observation_fixture(&revision);
        let mut graph: serde_json::Value =
            serde_json::from_str(report["raw_lock"].as_str().unwrap()).unwrap();
        graph["nodes"]["chosen-edge"]["inputs"] =
            serde_json::json!({"mvm-workspace":"renamed-workspace"});
        graph["nodes"]["renamed-workspace"] = serde_json::json!({
            "flake":false, "locked":{"type":"path","path":".."},
            "original":{"type":"path","path":".."}, "parent":["mvm"]
        });
        bind_fixture_graph(&mut report, &graph);
        std::fs::write(&path, report.to_string()).unwrap();
        read_input_observation(&path, "source-digest", &revision, "output").unwrap();
        for pointer in [
            "/nodes/renamed-workspace/locked/path",
            "/nodes/renamed-workspace/parent",
            "/nodes/renamed-workspace/flake",
            "/nodes/chosen-edge/locked/dir",
            "/nodes/chosen-edge/locked/narHash",
            "/nodes/chosen-edge/inputs/mvm-workspace",
        ] {
            let mut changed = graph.clone();
            *changed.pointer_mut(pointer).unwrap() = serde_json::json!("wrong");
            bind_fixture_graph(&mut report, &changed);
            std::fs::write(&path, report.to_string()).unwrap();
            assert!(
                read_input_observation(&path, "source-digest", &revision, "output").is_err(),
                "{pointer}"
            );
        }
        for (pointer, value) in [
            (
                "/nodes/renamed-workspace/locked",
                serde_json::json!({"type":"path","path":"..","dir":"external"}),
            ),
            (
                "/nodes/renamed-workspace/locked",
                serde_json::json!({"type":"path","path":"../.."}),
            ),
            (
                "/nodes/renamed-workspace/locked",
                serde_json::json!({"type":"path","path":"/work"}),
            ),
            ("/nodes/renamed-workspace/parent", serde_json::json!([])),
            (
                "/nodes/renamed-workspace/parent",
                serde_json::json!(["other"]),
            ),
            (
                "/nodes/chosen-edge/inputs/mvm-workspace",
                serde_json::json!(["mvm", "mvm-workspace"]),
            ),
        ] {
            let mut changed = graph.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            bind_fixture_graph(&mut report, &changed);
            std::fs::write(&path, report.to_string()).unwrap();
            assert!(
                read_input_observation(&path, "source-digest", &revision, "output").is_err(),
                "{pointer}"
            );
        }
        for (node, key, value) in [
            (
                "renamed-workspace",
                "inputs",
                serde_json::json!({"cycle":"renamed-workspace"}),
            ),
            ("chosen-edge", "parent", serde_json::json!(["mvm"])),
        ] {
            let mut changed = graph.clone();
            changed["nodes"][node][key] = value;
            bind_fixture_graph(&mut report, &changed);
            std::fs::write(&path, report.to_string()).unwrap();
            assert!(read_input_observation(&path, "source-digest", &revision, "output").is_err());
        }
        let mut changed = graph.clone();
        changed["nodes"]["chosen-edge"]["locked"]["ref"] = serde_json::json!("main");
        bind_fixture_graph(&mut report, &changed);
        std::fs::write(&path, report.to_string()).unwrap();
        assert!(read_input_observation(&path, "source-digest", &revision, "output").is_err());
    }

    #[test]
    fn non_native_observation_reader_binds_graph_bytes_and_returned_result() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report");
        let revision = "a".repeat(40);
        let valid = observation_fixture(&revision);
        std::fs::write(&path, valid.to_string()).unwrap();
        read_input_observation(&path, "source-digest", &revision, "output").unwrap();
        assert!(read_input_observation(&path, "other-input", &revision, "output").is_err());
        assert!(read_input_observation(&path, "source-digest", &revision, "other-output").is_err());
        for key in [
            "raw_lock",
            "raw_metadata",
            "job_id",
            "cmd_sha256",
            "expected_mvm_revision",
        ] {
            let mut malformed = valid.clone();
            malformed[key] = serde_json::json!(if key == "job_id" { "" } else { "wrong" });
            std::fs::write(&path, malformed.to_string()).unwrap();
            assert!(
                read_input_observation(&path, "source-digest", &revision, "output").is_err(),
                "{key}"
            );
        }
        std::fs::write(&path, b"{").unwrap();
        assert!(read_input_observation(&path, "source-digest", &revision, "output").is_err());
        std::fs::File::create(&path)
            .unwrap()
            .set_len(INPUT_OBSERVATION_MAX_BYTES + 1)
            .unwrap();
        assert!(read_input_observation(&path, "source-digest", &revision, "output").is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(read_input_observation(&path, "source-digest", &revision, "output").is_err());
    }

    #[test]
    fn non_native_observation_transport_is_not_promoted_to_shared_cache() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        let path = staging.join("frozen-input-observation.json");
        let revision = "a".repeat(40);
        let report = observation_fixture(&revision).to_string();
        std::fs::write(&path, &report).unwrap();
        std::fs::write(staging.join("rootfs.ext4"), b"rootfs").unwrap();
        assert!(take_input_observation(&path, "wrong-input", &revision, "output").is_err());
        assert!(path.exists());
        let bytes = take_input_observation(&path, "source-digest", &revision, "output").unwrap();
        assert_eq!(bytes, report.as_bytes());
        let cache = dir.path().join("cache");
        std::fs::rename(staging, &cache).unwrap();
        assert!(!cache.join("frozen-input-observation.json").exists());
        assert_eq!(std::fs::read(cache.join("rootfs.ext4")).unwrap(), b"rootfs");
    }

    #[test]
    fn non_native_observation_round_trips_existing_output_transport() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let revision = "a".repeat(40);
        let report = observation_fixture(&revision).to_string();
        std::fs::write(source.join("frozen-input-observation.json"), &report).unwrap();
        let disk = dir.path().join("output.img");
        crate::builder_disk_transport::create_output_disk(&disk, 1024 * 1024).unwrap();
        crate::builder_disk_transport::write_output_disk(&source, &disk).unwrap();
        let output = dir.path().join("out");
        let job = dir.path().join("job");
        std::fs::create_dir(&job).unwrap();
        crate::builder_vm_transport::extract_builder_transport_output(&disk, &output, &job)
            .unwrap();
        assert_eq!(
            read_input_observation(
                &output.join("frozen-input-observation.json"),
                "source-digest",
                &revision,
                "output"
            )
            .unwrap(),
            report.as_bytes()
        );
    }

    #[test]
    fn non_native_staging_owns_exact_bytes_and_rejects_mutation() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("flake.nix"),
            "github:tinylabscom/mvm/rev-a",
        )
        .unwrap();
        let expected = tree_digest(source.path()).unwrap();
        let frozen = FrozenInputs::stage(source.path(), &expected).unwrap();
        assert_ne!(source.path(), frozen.path());
        std::fs::write(
            source.path().join("flake.nix"),
            "github:tinylabscom/mvm/rev-b",
        )
        .unwrap();
        frozen.verify().unwrap();
        assert!(FrozenInputs::stage(source.path(), &expected).is_err());
        std::fs::write(frozen.path().join("flake.nix"), "changed").unwrap();
        assert!(frozen.verify().is_err());
    }

    #[test]
    fn non_native_staging_refuses_any_filtering_of_locked_bytes() {
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir(source.path().join("target")).unwrap();
        std::fs::write(source.path().join("target/input"), "locked").unwrap();
        let digest = tree_digest(source.path()).unwrap();
        assert!(FrozenInputs::stage(source.path(), &digest).is_err());
    }

    #[test]
    fn non_native_concurrent_sources_and_pins_have_disjoint_owned_staging() {
        let handles: Vec<_> = ["rev-a", "rev-b"]
            .into_iter()
            .map(|pin| {
                std::thread::spawn(move || {
                    let source = tempfile::tempdir().unwrap();
                    std::fs::write(
                        source.path().join("flake.nix"),
                        format!("github:tinylabscom/mvm/{pin}"),
                    )
                    .unwrap();
                    std::fs::write(source.path().join("workload.json"), "same-workload").unwrap();
                    std::fs::write(source.path().join("source"), pin).unwrap();
                    FrozenInputs::stage(source.path(), &tree_digest(source.path()).unwrap())
                        .unwrap()
                })
            })
            .collect();
        let frozen: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_ne!(frozen[0].path(), frozen[1].path());
        assert_ne!(
            tree_digest(frozen[0].path()).unwrap(),
            tree_digest(frozen[1].path()).unwrap()
        );
        let first = frozen[0].path().to_path_buf();
        let second = frozen[1].path().to_path_buf();
        drop(frozen);
        assert!(!first.exists());
        assert!(!second.exists());
    }
}
