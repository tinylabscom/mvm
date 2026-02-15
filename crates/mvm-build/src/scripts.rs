use anyhow::{Result, anyhow};
use std::collections::{BTreeMap, BTreeSet};

fn script_source(name: &str) -> Option<&'static str> {
    match name {
        "ensure_builder_artifacts" => Some(include_str!(
            "../../../resources/builder_scripts/ensure_builder_artifacts.sh.tera"
        )),
        "launch_firecracker_ssh" => Some(include_str!(
            "../../../resources/builder_scripts/launch_firecracker_ssh.sh.tera"
        )),
        "launch_firecracker_vsock" => Some(include_str!(
            "../../../resources/builder_scripts/launch_firecracker_vsock.sh.tera"
        )),
        "builder_keygen" => Some(include_str!(
            "../../../resources/builder_scripts/builder_keygen.sh.tera"
        )),
        "refresh_builder_rootfs" => Some(include_str!(
            "../../../resources/builder_scripts/refresh_builder_rootfs.sh.tera"
        )),
        "download_builder_artifacts" => Some(include_str!(
            "../../../resources/builder_scripts/download_builder_artifacts.sh.tera"
        )),
        "sync_local_flake" => Some(include_str!(
            "../../../resources/builder_scripts/sync_local_flake.sh.tera"
        )),
        "run_nix_build_ssh" => Some(include_str!(
            "../../../resources/builder_scripts/run_nix_build_ssh.sh.tera"
        )),
        "extract_artifacts_ssh" => Some(include_str!(
            "../../../resources/builder_scripts/extract_artifacts_ssh.sh.tera"
        )),
        "extract_artifacts_vsock_disk" => Some(include_str!(
            "../../../resources/builder_scripts/extract_artifacts_vsock_disk.sh.tera",
        )),
        _ => None,
    }
}

fn is_placeholder_key(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c == '-' || c.is_ascii_alphanumeric())
}

fn find_placeholders(s: &str) -> BTreeSet<String> {
    let bytes = s.as_bytes();
    let mut out = BTreeSet::new();

    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'{' && bytes[i + 1] == b'{' {
            let start = i + 2;
            let mut j = start;
            while j + 1 < bytes.len() {
                if bytes[j] == b'}' && bytes[j + 1] == b'}' {
                    let inner = s[start..j].trim();
                    if is_placeholder_key(inner) {
                        out.insert(inner.to_string());
                    }
                    i = j + 2;
                    break;
                }
                j += 1;
            }
            if j + 1 >= bytes.len() {
                break;
            }
            continue;
        }
        i += 1;
    }

    out
}

pub fn render_script(name: &str, context: &BTreeMap<&str, String>) -> Result<String> {
    let template = script_source(name)
        .ok_or_else(|| anyhow!("unknown script template: {name}"))?
        .to_string();

    let required = find_placeholders(&template);
    let missing: Vec<String> = required
        .iter()
        .filter(|k| !context.contains_key(k.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(anyhow!(
            "missing template variable(s) for script {name}: {}",
            missing.join(", ")
        ));
    }

    let mut out = template;

    for (key, val) in context {
        out = out.replace(&format!("{{{{{key}}}}}"), val);
    }

    let unresolved = find_placeholders(&out);
    if !unresolved.is_empty() {
        return Err(anyhow!(
            "unresolved template variable(s) in script {name}: {}",
            unresolved.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    Ok(out)
}
