use anyhow::Result;
use chrono::Utc;
use mvm_core::template::{TemplateConfig, TemplateSpec, template_dir, templates_base_dir};
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
    let flake_ref = resolve_flake_ref(flake);
    let ts = now_iso();
    let spec = TemplateSpec {
        schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
        template_id: name.to_string(),
        flake_ref,
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

/// Resolve a flake reference to an absolute path if it's a local path.
///
/// Relative paths like "." or "../foo" are resolved against CWD so that
/// `nix build` works regardless of which directory the build runs from.
/// Remote flake refs (e.g., "github:user/repo") are passed through unchanged.
fn resolve_flake_ref(flake: &str) -> String {
    // Remote flake refs contain ":" (github:, git+https:, path:, etc.)
    if flake.contains(':') {
        return flake.to_string();
    }
    // Local path — resolve to absolute
    match std::path::Path::new(flake).canonicalize() {
        Ok(abs) => abs.to_string_lossy().to_string(),
        Err(_) => flake.to_string(),
    }
}

/// Initialize an empty template directory layout (idempotent).
pub fn init(name: &str, local: bool, base_dir: &str, preset: &str) -> Result<()> {
    if local {
        let dir = std::path::Path::new(base_dir).join(name);
        scaffold_template_files(&dir, name, preset)?;
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
    // Resolve once so all variants share the same absolute path.
    let flake_ref = resolve_flake_ref(flake);
    for role in roles {
        let name = format!("{base}-{role}");
        create_single(&name, &flake_ref, profile, role, cpus, mem, data_disk)?;
    }
    Ok(())
}

pub fn list(json: bool) -> Result<()> {
    let vm_items = tmpl::template_list()?;
    let local_items = local_templates(Path::new("."))?;

    let base = templates_base_dir();

    if json {
        #[derive(serde::Serialize)]
        struct Out {
            vm_base: String,
            vm: Vec<String>,
            local_base: String,
            local: Vec<String>,
        }
        let out = Out {
            vm_base: base,
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

    println!("Templates ({base}):");
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

pub fn build(
    name: &str,
    force: bool,
    snapshot: bool,
    config: Option<&str>,
    update_hash: bool,
) -> Result<()> {
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
                schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
                template_id: template_name.clone(),
                flake_ref: resolve_flake_ref(&cfg.flake_ref),
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
            if snapshot {
                tmpl::template_build_with_snapshot(&template_name, force, update_hash)?;
            } else {
                tmpl::template_build(&template_name, force, update_hash)?;
            }
        }
        Ok(())
    } else if snapshot {
        tmpl::template_build_with_snapshot(name, force, update_hash)
    } else {
        tmpl::template_build(name, force, update_hash)
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

pub fn edit(
    name: &str,
    flake: Option<&str>,
    profile: Option<&str>,
    role: Option<&str>,
    cpus: Option<u8>,
    mem: Option<u32>,
    data_disk: Option<u32>,
) -> Result<()> {
    // Load existing template spec
    let mut spec = tmpl::template_load(name)?;

    // Update fields if provided
    if let Some(f) = flake {
        spec.flake_ref = resolve_flake_ref(f);
    }
    if let Some(p) = profile {
        spec.profile = p.to_string();
    }
    if let Some(r) = role {
        spec.role = r.to_string();
    }
    if let Some(c) = cpus {
        spec.vcpus = c;
    }
    if let Some(m) = mem {
        spec.mem_mib = m;
    }
    if let Some(d) = data_disk {
        spec.data_disk_mib = d;
    }

    // Update timestamp
    spec.updated_at = now_iso();

    // Save updated spec
    tmpl::template_create(&spec)?;

    println!("Updated template '{}'", name);
    println!(" vCPUs:   {}", spec.vcpus);
    println!(" MemMiB:  {}", spec.mem_mib);
    println!(" DataMiB: {}", spec.data_disk_mib);
    println!(
        "\nRun 'mvmctl template build {} --force' to rebuild with new settings",
        name
    );

    Ok(())
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

fn flake_content_for_preset(preset: &str) -> Result<&'static str> {
    match preset {
        "minimal" => Ok(include_str!("../resources/template_scaffold/flake.nix")),
        "http" => Ok(include_str!(
            "../resources/template_scaffold/flake-http.nix"
        )),
        "postgres" => Ok(include_str!(
            "../resources/template_scaffold/flake-postgres.nix"
        )),
        "worker" => Ok(include_str!(
            "../resources/template_scaffold/flake-worker.nix"
        )),
        other => anyhow::bail!(
            "Unknown preset {:?}. Valid presets: minimal, http, postgres, worker",
            other
        ),
    }
}

fn scaffold_template_files(dir: &Path, name: &str, preset: &str) -> Result<()> {
    fs::create_dir_all(dir)?;

    let gitignore = dir.join(".gitignore");
    if !gitignore.exists() {
        fs::write(
            &gitignore,
            include_str!("../resources/template_scaffold/.gitignore"),
        )?;
    }

    let flake_path = dir.join("flake.nix");
    if !flake_path.exists() {
        fs::write(&flake_path, flake_content_for_preset(preset)?)?;
    }

    let readme_path = dir.join("README.md");
    if !readme_path.exists() {
        let content =
            include_str!("../resources/template_scaffold/README.md").replace("{{name}}", name);
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
        fs::write(&baseline_path, include_str!("../resources/baseline.nix"))?;
    }
    Ok(())
}
