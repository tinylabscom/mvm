use anyhow::Result;
use chrono::Utc;
use mvm_core::template::{TemplateConfig, TemplateSpec, template_dir};
use mvm_runtime::vm::template::lifecycle as tmpl;
use std::fs;
use std::fs::read_dir;
use std::path::Path;

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn create_single(
    name: &str,
    flake: &str,
    profile: &str,
    role: &str,
    cpus: u8,
    mem: u32,
    data_disk: u32,
) -> Result<()> {
    let ts = now_iso();
    let spec = TemplateSpec {
        template_id: name.to_string(),
        flake_ref: flake.to_string(),
        profile: profile.to_string(),
        role: role.to_string(),
        vcpus: cpus,
        mem_mib: mem,
        data_disk_mib: data_disk,
        created_at: ts.clone(),
        updated_at: ts,
    };
    tmpl::template_create(&spec)
}

/// Initialize an empty template directory layout (idempotent).
pub fn init(name: &str, local: bool, base_dir: &str) -> Result<()> {
    if local {
        let dir = std::path::Path::new(base_dir).join(name);
        scaffold_template_files(&dir, name)?;
        return Ok(());
    }
    tmpl::template_init(name)
}

pub fn create_multi(
    base: &str,
    flake: &str,
    profile: &str,
    roles: &[String],
    cpus: u8,
    mem: u32,
    data_disk: u32,
) -> Result<()> {
    for role in roles {
        let name = format!("{base}-{role}");
        create_single(&name, flake, profile, role, cpus, mem, data_disk)?;
    }
    Ok(())
}

pub fn list(json: bool) -> Result<()> {
    let vm_items = tmpl::template_list()?;
    let local_items = local_templates(Path::new("."))?;

    if json {
        #[derive(serde::Serialize)]
        struct Out {
            vm_base: &'static str,
            vm: Vec<String>,
            local_base: String,
            local: Vec<String>,
        }
        let out = Out {
            vm_base: "/var/lib/mvm/templates",
            vm: vm_items,
            local_base: std::env::current_dir()
                .unwrap_or_else(|_| Path::new(".").to_path_buf())
                .display()
                .to_string(),
            local: local_items,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("VM templates (default: /var/lib/mvm/templates):");
    if vm_items.is_empty() {
        println!("  (none)");
    } else {
        for t in &vm_items {
            println!("  {}", t);
        }
    }

    println!("\nLocal templates (base: ./):");
    if local_items.is_empty() {
        println!("  (none)");
    } else {
        for t in &local_items {
            println!("  {}", t);
        }
    }

    Ok(())
}

pub fn info(name: &str, json: bool) -> Result<()> {
    let spec = tmpl::template_load(name)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&spec)?);
    } else {
        println!("Template: {}", spec.template_id);
        println!(" Flake:   {}", spec.flake_ref);
        println!(" Profile: {}", spec.profile);
        println!(" Role:    {}", spec.role);
        println!(" vCPUs:   {}", spec.vcpus);
        println!(" MemMiB:  {}", spec.mem_mib);
        println!(" DataMiB: {}", spec.data_disk_mib);
        println!(" Created: {}", spec.created_at);
        println!(" Updated: {}", spec.updated_at);
        println!(" Path:    {}", template_dir(name));
    }
    Ok(())
}

pub fn delete(name: &str, force: bool) -> Result<()> {
    tmpl::template_delete(name, force)
}

pub fn build(name: &str, force: bool, config: Option<&str>) -> Result<()> {
    if let Some(cfg_path) = config {
        let cfg = load_config(cfg_path)?;
        for variant in &cfg.variants {
            let base = if !cfg.template_id.is_empty() {
                cfg.template_id.clone()
            } else {
                name.to_string()
            };
            let template_name = if !variant.name.is_empty() {
                variant.name.clone()
            } else {
                format!("{base}-{}", variant.role)
            };

            let ts = now_iso();
            let spec = TemplateSpec {
                template_id: template_name.clone(),
                flake_ref: cfg.flake_ref.clone(),
                profile: if variant.profile.is_empty() {
                    cfg.profile.clone()
                } else {
                    variant.profile.clone()
                },
                role: variant.role.clone(),
                vcpus: variant.vcpus,
                mem_mib: variant.mem_mib,
                data_disk_mib: variant.data_disk_mib,
                created_at: ts.clone(),
                updated_at: ts,
            };
            tmpl::template_create(&spec)?;
            tmpl::template_build(&template_name, force)?;
        }
        Ok(())
    } else {
        tmpl::template_build(name, force)
    }
}

pub fn push(name: &str, revision: Option<&str>) -> Result<()> {
    tmpl::template_push(name, revision)
}

pub fn pull(name: &str, revision: Option<&str>) -> Result<()> {
    tmpl::template_pull(name, revision)
}

pub fn verify(name: &str, revision: Option<&str>) -> Result<()> {
    tmpl::template_verify(name, revision)
}

fn load_config(path: &str) -> Result<TemplateConfig> {
    let data = fs::read_to_string(Path::new(path))
        .map_err(|e| anyhow::anyhow!("Failed to read template config {}: {}", path, e))?;
    let cfg: TemplateConfig = toml::from_str(&data)
        .map_err(|e| anyhow::anyhow!("Failed to parse template config {}: {}", path, e))?;
    Ok(cfg)
}

fn local_templates(base: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    if let Ok(entries) = read_dir(base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let artifacts = path.join("artifacts").join("revisions");
                if artifacts.exists()
                    && let Some(name) = path.file_name().and_then(|s| s.to_str())
                {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    Ok(names)
}

fn scaffold_template_files(dir: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(dir)?;

    let gitignore = dir.join(".gitignore");
    if !gitignore.exists() {
        fs::write(
            &gitignore,
            include_str!("../../../resources/template_scaffold/.gitignore"),
        )?;
    }

    let flake_path = dir.join("flake.nix");
    if !flake_path.exists() {
        fs::write(
            &flake_path,
            include_str!("../../../resources/template_scaffold/flake.nix"),
        )?;
    }

    let readme_path = dir.join("README.md");
    if !readme_path.exists() {
        let content = include_str!("../../../resources/template_scaffold/README.md")
            .replace("{{name}}", name);
        fs::write(&readme_path, content)?;
    }

    // Scaffold the baseline NixOS guest config. The guest agent modules
    // come from the mvm-src flake input automatically.
    scaffold_mvm_baseline(dir)?;

    Ok(())
}

/// Write the mvm baseline NixOS config into the scaffold directory.
///
/// The guest agent modules come from the `mvm-src` flake input,
/// but the baseline guest config is scaffolded locally so users can customize it.
fn scaffold_mvm_baseline(dir: &Path) -> Result<()> {
    let baseline_path = dir.join("baseline.nix");
    if !baseline_path.exists() {
        fs::write(
            &baseline_path,
            include_str!("../../../nix/openclaw/guests/baseline.nix"),
        )?;
    }
    Ok(())
}
