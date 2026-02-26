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
        scaffold_template_config(&dir, name)?;
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
    // Ensure base directories
    create_dir_all(dir)?;
    create_dir_all(dir.join("guests"))?;
    create_dir_all(dir.join("roles"))?;
    create_dir_all(dir.join("guests/profiles"))?;
    create_dir_all(dir.join("modules"))?;
    // ignore build outputs/artifacts
    let gitignore = dir.join(".gitignore");
    if !gitignore.exists() {
        write_file(
            &gitignore,
            include_str!("../../../resources/template_scaffold/.gitignore"),
        )?;
    }

    // flake.nix (microvm-aware scaffold)
    let flake_path = dir.join("flake.nix");
    if !flake_path.exists() {
        write_file(
            &flake_path,
            include_str!("../../../resources/template_scaffold/flake.nix"),
        )?;
    }

    // mvm-profiles.toml
    let profiles_path = dir.join("mvm-profiles.toml");
    if !profiles_path.exists() {
        write_file(
            &profiles_path,
            include_str!("../../../resources/template_scaffold/mvm-profiles.toml"),
        )?;
    }

    // guests/baseline.nix (stub)
    let guest_baseline = dir.join("guests").join("baseline.nix");
    if !guest_baseline.exists() {
        write_file(
            &guest_baseline,
            include_str!("../../../resources/template_scaffold/guests/baseline.nix"),
        )?;
    }

    // guest profiles stubs (gateway/worker)
    let gw_profile = dir.join("guests/profiles").join("gateway.nix");
    if !gw_profile.exists() {
        write_file(
            &gw_profile,
            include_str!("../../../resources/template_scaffold/guests/profiles/gateway.nix"),
        )?;
    }
    let worker_profile = dir.join("guests/profiles").join("worker.nix");
    if !worker_profile.exists() {
        write_file(
            &worker_profile,
            include_str!("../../../resources/template_scaffold/guests/profiles/worker.nix"),
        )?;
    }

    // roles/worker.nix stub
    let role_worker = dir.join("roles").join("worker.nix");
    if !role_worker.exists() {
        write_file(
            &role_worker,
            include_str!("../../../resources/template_scaffold/roles/worker.nix"),
        )?;
    }

    // roles/gateway.nix stub
    let role_gateway = dir.join("roles").join("gateway.nix");
    if !role_gateway.exists() {
        write_file(
            &role_gateway,
            include_str!("../../../resources/template_scaffold/roles/gateway.nix"),
        )?;
    }

    // guests/default.nix (stub)
    let guest_default = dir.join("guests").join("default.nix");
    if !guest_default.exists() {
        write_file(
            &guest_default,
            include_str!("../../../resources/template_scaffold/guests/default.nix"),
        )?;
    }

    // roles/README (guidance)
    let roles_readme = dir.join("roles").join("README.md");
    if !roles_readme.exists() {
        write_file(
            &roles_readme,
            include_str!("../../../resources/template_scaffold/roles/README.md"),
        )?;
    }

    // README
    let readme_path = dir.join("README.md");
    if !readme_path.exists() {
        let content = include_str!("../../../resources/template_scaffold/README.md")
            .replace("{{name}}", name);
        write_file(&readme_path, &content)?;
    }

    Ok(())
}

fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    fs::create_dir_all(path)?;
    Ok(())
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn scaffold_template_config(dir: &Path, name: &str) -> Result<()> {
    let cfg_path = dir.join("template.toml");
    if cfg_path.exists() {
        return Ok(());
    }
    let content = include_str!("../../../resources/template_scaffold/template.toml")
        .replace("{{name}}", name);
    write_file(&cfg_path, &content)
}
