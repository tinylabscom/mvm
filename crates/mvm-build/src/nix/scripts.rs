use anyhow::{Result, anyhow, bail};
use std::collections::BTreeMap;

// NOTE: Builder script templates support only simple `{{ var }}` placeholders.
// Keep script logic in shell and pass pre-rendered values through the context.

fn script_source(name: &str) -> Option<&'static str> {
    match name {
        "ensure_builder_artifacts" => Some(include_str!(
            "../../resources/builder_scripts/ensure_builder_artifacts.sh.tera"
        )),
        "launch_firecracker_vsock" => Some(include_str!(
            "../../resources/builder_scripts/launch_firecracker_vsock.sh.tera"
        )),
        "refresh_builder_rootfs" => Some(include_str!(
            "../../resources/builder_scripts/refresh_builder_rootfs.sh.tera"
        )),
        "download_builder_artifacts" => Some(include_str!(
            "../../resources/builder_scripts/download_builder_artifacts.sh.tera"
        )),
        "extract_artifacts_vsock_disk" => Some(include_str!(
            "../../resources/builder_scripts/extract_artifacts_vsock_disk.sh.tera"
        )),
        "run_nix_build_host" => Some(include_str!(
            "../../resources/builder_scripts/run_nix_build_host.sh.tera"
        )),
        "extract_artifacts_host" => Some(include_str!(
            "../../resources/builder_scripts/extract_artifacts_host.sh.tera"
        )),
        _ => None,
    }
}

#[cfg(test)]
fn script_names() -> &'static [&'static str] {
    &[
        "ensure_builder_artifacts",
        "launch_firecracker_vsock",
        "refresh_builder_rootfs",
        "download_builder_artifacts",
        "extract_artifacts_vsock_disk",
        "run_nix_build_host",
        "extract_artifacts_host",
    ]
}

pub fn render_script(name: &str, context: &BTreeMap<&str, String>) -> Result<String> {
    let src = script_source(name).ok_or_else(|| anyhow!("unknown script template: {name}"))?;
    validate_template(name, src)?;

    let mut rendered = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(start) = rest.find("{{") {
        rendered.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find("}}") else {
            bail!("unterminated template placeholder in script {name}");
        };
        let key = after_start[..end].trim();
        if key.is_empty() {
            bail!("empty template placeholder in script {name}");
        }
        let value = context
            .get(key)
            .ok_or_else(|| anyhow!("missing template variable {key:?} for script {name}"))?;
        rendered.push_str(value);
        rest = &after_start[end + 2..];
    }
    rendered.push_str(rest);
    Ok(rendered)
}

fn validate_template(name: &str, src: &str) -> Result<()> {
    let mut rest = src;
    while let Some(start) = rest.find("{{") {
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find("}}") else {
            bail!("unterminated template placeholder in script {name}");
        };
        let key = after_start[..end].trim();
        if key.is_empty() {
            bail!("empty template placeholder in script {name}");
        }
        if !key
            .chars()
            .all(|c| c == '_' || c == '-' || c.is_ascii_alphanumeric())
        {
            bail!("unsupported template placeholder {key:?} in script {name}");
        }
        rest = &after_start[end + 2..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_templates_parse() {
        for name in script_names() {
            let src = script_source(name).expect("script listed in script_names should exist");
            validate_template(name, src).expect("builder templates should parse");
        }
    }

    #[test]
    fn test_missing_var_fails() {
        let mut ctx = BTreeMap::new();
        ctx.insert("run_dir", "/tmp".to_string());
        // launch_firecracker_vsock requires more vars than just run_dir.
        let err = render_script("launch_firecracker_vsock", &ctx).unwrap_err();
        let msg = format!("{err:#}");
        eprintln!("{msg}");
        assert!(msg.contains("launch_firecracker_vsock"));
        assert!(msg.contains("missing template variable"));
    }

    #[test]
    fn test_smoke_render_launch_firecracker_vsock() {
        let mut ctx = BTreeMap::new();
        ctx.insert("run_dir", "/tmp/mvm".to_string());
        ctx.insert("socket", "/tmp/mvm/firecracker.socket".to_string());
        ctx.insert("config", "/tmp/mvm/fc-builder.json".to_string());
        ctx.insert("log", "/tmp/mvm/firecracker.log".to_string());
        ctx.insert("pid", "/tmp/mvm/fc.pid".to_string());
        ctx.insert("out_disk", "/tmp/mvm/build-out.ext4".to_string());
        ctx.insert("vsock_uds", "/tmp/mvm/builder.vsock".to_string());

        let rendered =
            render_script("launch_firecracker_vsock", &ctx).expect("render should succeed");
        assert!(rendered.contains("/tmp/mvm"));
        assert!(rendered.contains("/tmp/mvm/firecracker.socket"));
        assert!(rendered.contains("/tmp/mvm/fc-builder.json"));
    }

    #[test]
    fn test_refresh_builder_rootfs_renders_awk_uid_gid() {
        let mut ctx = BTreeMap::new();
        ctx.insert("builder_dir", "/var/lib/mvm/builder".to_string());
        ctx.insert("inject_ssh", "yes".to_string());
        ctx.insert("auth_keys", "ssh-ed25519 AAAA test".to_string());
        ctx.insert("agent_src", "/tmp/mvm-builder-agent".to_string());
        ctx.insert("agent_dst", "/usr/local/bin/mvm-builder-agent".to_string());
        ctx.insert(
            "agent_service",
            "/etc/systemd/system/mvm-builder-agent.service".to_string(),
        );

        let rendered =
            render_script("refresh_builder_rootfs", &ctx).expect("render should succeed");
        assert!(rendered.contains(r#"awk -F: '/^ubuntu:/{print $3 ":" $4}'"#));
    }
}
