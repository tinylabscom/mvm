use anyhow::{Context, Result, anyhow};
use std::collections::BTreeMap;
use std::sync::OnceLock;

// NOTE: Builder script templates use Tera's `{{ var }}` syntax.
// If you need to embed a literal `{{...}}` string (e.g. Go templates like `{{.Status}}`)
// inside a builder script, wrap it in a raw block:
//   {% raw %}{{.Status}}{% endraw %}

static TERA: OnceLock<Result<tera::Tera>> = OnceLock::new();

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
            "../../../resources/builder_scripts/extract_artifacts_vsock_disk.sh.tera"
        )),
        "run_nix_build_host" => Some(include_str!(
            "../../../resources/builder_scripts/run_nix_build_host.sh.tera"
        )),
        "extract_artifacts_host" => Some(include_str!(
            "../../../resources/builder_scripts/extract_artifacts_host.sh.tera"
        )),
        "inject_guest_agent" => Some(include_str!(
            "../../../resources/builder_scripts/inject_guest_agent.sh.tera"
        )),
        _ => None,
    }
}

fn script_names() -> &'static [&'static str] {
    &[
        "ensure_builder_artifacts",
        "launch_firecracker_ssh",
        "launch_firecracker_vsock",
        "builder_keygen",
        "refresh_builder_rootfs",
        "download_builder_artifacts",
        "sync_local_flake",
        "run_nix_build_ssh",
        "extract_artifacts_ssh",
        "extract_artifacts_vsock_disk",
        "run_nix_build_host",
        "extract_artifacts_host",
        "inject_guest_agent",
    ]
}

fn build_tera() -> Result<tera::Tera> {
    let mut tera = tera::Tera::default();
    // Shell scripts must not be HTML-escaped.
    tera.autoescape_on(vec![]);

    for name in script_names() {
        let src = script_source(name)
            .ok_or_else(|| anyhow!("builder script template source not found: {name}"))?;
        tera.add_raw_template(name, src)
            .map_err(anyhow::Error::new)
            .with_context(|| format!("Failed to parse builder script template {name}"))?;
    }

    Ok(tera)
}

fn tera_instance() -> Result<&'static tera::Tera> {
    match TERA.get_or_init(build_tera) {
        Ok(t) => Ok(t),
        Err(e) => {
            Err(anyhow!(e.to_string())).context("Failed to initialize builder script templates")
        }
    }
}

pub fn render_script(name: &str, context: &BTreeMap<&str, String>) -> Result<String> {
    let tera = tera_instance()?;

    if script_source(name).is_none() {
        return Err(anyhow!("unknown script template: {name}"));
    }

    let mut ctx = tera::Context::new();
    for (k, v) in context {
        ctx.insert(*k, v);
    }

    tera.render(name, &ctx)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("Failed to render script {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_templates_parse() {
        build_tera().expect("builder templates should parse");
    }

    #[test]
    fn test_missing_var_fails() {
        let mut ctx = BTreeMap::new();
        ctx.insert("run_dir", "/tmp".to_string());
        // launch_firecracker_ssh requires more vars than just run_dir.
        let err = render_script("launch_firecracker_ssh", &ctx).unwrap_err();
        let msg = format!("{err:#}");
        eprintln!("{msg}");
        assert!(msg.contains("launch_firecracker_ssh"));
        // Don't overfit the exact wording, but ensure it's a render-time failure surfaced via Tera.
        assert!(msg.contains("Failed to render script launch_firecracker_ssh"));
    }

    #[test]
    fn test_smoke_render_launch_firecracker_ssh() {
        let mut ctx = BTreeMap::new();
        ctx.insert("run_dir", "/tmp/mvm".to_string());
        ctx.insert("socket", "/tmp/mvm/firecracker.socket".to_string());
        ctx.insert("config", "/tmp/mvm/fc-builder.json".to_string());
        ctx.insert("log", "/tmp/mvm/firecracker.log".to_string());
        ctx.insert("pid", "/tmp/mvm/fc.pid".to_string());

        let rendered =
            render_script("launch_firecracker_ssh", &ctx).expect("render should succeed");
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
