use anyhow::{Context, Result};
use chrono::Utc;
use mvm_core::template::{TemplateConfig, TemplateSpec, template_dir, templates_base_dir};
use mvm_runtime::vm::template::lifecycle as tmpl;
use std::fs;
use std::fs::read_dir;
use std::path::Path;
use std::time::Duration;

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Inputs to [`create_single`] / [`create_multi`]. Bundled into a
/// struct so adding new spec fields (e.g. plan 32's
/// `default_network_policy`) doesn't trip clippy's
/// `too_many_arguments` lint and doesn't churn every callsite.
#[derive(Debug, Clone)]
pub struct CreateParams<'a> {
    pub flake: &'a str,
    pub profile: &'a str,
    pub role: &'a str,
    pub cpus: u8,
    pub mem: u32,
    pub data_disk: u32,
    pub default_network_policy: Option<mvm_core::policy::network_policy::NetworkPolicy>,
}

pub fn create_single(name: &str, params: CreateParams<'_>) -> Result<()> {
    let flake_ref = resolve_flake_ref(params.flake);
    let ts = now_iso();
    let spec = TemplateSpec {
        schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
        template_id: name.to_string(),
        flake_ref,
        profile: params.profile.to_string(),
        role: params.role.to_string(),
        vcpus: params.cpus,
        mem_mib: params.mem,
        data_disk_mib: params.data_disk,
        created_at: ts.clone(),
        updated_at: ts,
        default_network_policy: params.default_network_policy,
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
pub fn init(
    name: &str,
    local: bool,
    base_dir: &str,
    preset: Option<&str>,
    prompt: Option<&str>,
) -> Result<()> {
    if local {
        let selected_preset = resolve_scaffold_preset(preset, prompt);
        let dir = std::path::Path::new(base_dir).join(name);
        scaffold_template_files(&dir, name, &selected_preset, prompt)?;
        return Ok(());
    }
    if prompt.is_some() {
        anyhow::bail!("--prompt currently requires --local");
    }
    tmpl::template_init(name)
}

pub fn create_multi(base: &str, roles: &[String], params: CreateParams<'_>) -> Result<()> {
    // Resolve once so all variants share the same absolute path.
    let flake_ref = resolve_flake_ref(params.flake);
    for role in roles {
        let name = format!("{base}-{role}");
        create_single(
            &name,
            CreateParams {
                flake: &flake_ref,
                profile: params.profile,
                role,
                cpus: params.cpus,
                mem: params.mem,
                data_disk: params.data_disk,
                default_network_policy: params.default_network_policy.clone(),
            },
        )?;
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
    let revision = tmpl::template_load_current_revision(name)?;

    if json {
        #[derive(serde::Serialize)]
        struct InfoOut {
            spec: TemplateSpec,
            revision: Option<mvm_core::template::TemplateRevision>,
            path: String,
        }
        let out = InfoOut {
            spec,
            revision,
            path: template_dir(name),
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Template: {}", spec.template_id);
        println!("  Flake:   {}", spec.flake_ref);
        println!("  Profile: {}", spec.profile);
        println!("  Role:    {}", spec.role);
        println!("  vCPUs:   {}", spec.vcpus);
        println!("  MemMiB:  {}", spec.mem_mib);
        println!("  DataMiB: {}", spec.data_disk_mib);
        println!("  Created: {}", spec.created_at);
        println!("  Updated: {}", spec.updated_at);
        println!("  Path:    {}", template_dir(name));
        if let Some(policy) = &spec.default_network_policy {
            use mvm_core::policy::network_policy::NetworkPolicy;
            let summary = match policy {
                NetworkPolicy::Preset { preset } => format!("preset={preset}"),
                NetworkPolicy::AllowList { rules } => {
                    let hosts: Vec<String> = rules.iter().map(|r| r.to_string()).collect();
                    format!("allowlist=[{}]", hosts.join(", "))
                }
            };
            println!("  Network: {summary}  (default; mvmctl up flags override)");
        }

        if let Some(rev) = &revision {
            use mvm_core::pool::format_bytes;
            println!();
            println!("Current revision:");
            println!(
                "  Hash:    {}",
                &rev.revision_hash[..rev.revision_hash.len().min(12)]
            );
            println!("  Built:   {}", rev.built_at);
            if let Some(sizes) = &rev.artifact_paths.sizes {
                println!("  Kernel:  {}", format_bytes(sizes.vmlinux_bytes));
                println!("  Rootfs:  {}", format_bytes(sizes.rootfs_bytes));
                if let Some(initrd) = sizes.initrd_bytes {
                    println!("  Initrd:  {}", format_bytes(initrd));
                }
                println!("  Total:   {}", format_bytes(sizes.total_bytes()));
                if let Some(closure) = sizes.nix_closure_bytes {
                    println!("  Closure: {}", format_bytes(closure));
                }
            }

            match &rev.snapshot {
                Some(snap) => {
                    println!();
                    println!("Snapshot:");
                    println!("  Created: {}", snap.created_at);
                    println!("  VM state: {}", format_bytes(snap.vmstate_size_bytes));
                    println!("  Memory:   {}", format_bytes(snap.mem_size_bytes));
                    println!(
                        "  Total:    {}",
                        format_bytes(snap.vmstate_size_bytes + snap.mem_size_bytes)
                    );
                }
                None => {
                    println!();
                    println!("Snapshot: (none)");
                }
            }
        } else {
            println!();
            println!("Revision: (not yet built)");
        }
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
                // The TOML-driven `template build --config` path doesn't
                // expose a per-variant network policy yet; callers that
                // want a default use `mvmctl template create
                // --network-preset` instead. Future work in plan 32 §D
                // ergonomic follow-up: extend TemplateConfig variants
                // with a network field.
                default_network_policy: None,
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
        // Check if the current backend supports snapshots.
        // Snapshots are Firecracker-specific; Apple Container and Docker
        // backends only support image-only templates.
        let backend = mvm_runtime::vm::backend::AnyBackend::auto_select();
        if backend.capabilities().snapshots {
            tmpl::template_build_with_snapshot(name, force, update_hash)
        } else {
            crate::ui::warn(&format!(
                "Backend '{}' does not support snapshots. Building image-only template.",
                backend.name()
            ));
            tmpl::template_build(name, force, update_hash)
        }
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
        "python" => Ok(include_str!(
            "../resources/template_scaffold/flake-python.nix"
        )),
        other => anyhow::bail!(
            "Unknown preset {:?}. Valid presets: minimal, http, postgres, worker, python",
            other
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScaffoldFeature {
    Python,
    Http,
    Postgres,
    Worker,
}

impl ScaffoldFeature {
    fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Http => "http",
            Self::Postgres => "postgres",
            Self::Worker => "worker",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct GeneratedTemplateSpec {
    primary_preset: String,
    features: Vec<ScaffoldFeature>,
    http_port: Option<u16>,
    health_path: Option<String>,
    worker_interval_secs: Option<u32>,
    python_entrypoint: Option<String>,
}

#[derive(Debug)]
struct PromptGenerationResult {
    spec: GeneratedTemplateSpec,
    details: PromptGenerationDetails,
}

#[derive(Debug)]
struct PromptGenerationDetails {
    generation_mode: String,
    provider: Option<String>,
    model: Option<String>,
    summary: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug)]
struct LlmGenerationConfig {
    provider: LlmProvider,
    base_url: String,
    model: String,
    api_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LlmProvider {
    OpenAi,
    Local,
}

#[derive(Debug, serde::Deserialize)]
struct OpenAiTemplatePlan {
    schema_version: u8,
    summary: String,
    primary_preset: String,
    features: Vec<String>,
    http_port: Option<u16>,
    health_path: Option<String>,
    worker_interval_secs: Option<u32>,
    python_entrypoint: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug)]
struct ValidatedOpenAiPlan {
    spec: GeneratedTemplateSpec,
    summary: String,
    notes: Vec<String>,
}

fn generated_template_spec(preset: Option<&str>, prompt: &str) -> GeneratedTemplateSpec {
    let mut features = infer_prompt_features(prompt);
    let primary_preset = resolve_scaffold_preset(preset, Some(prompt));

    if let Some(primary_feature) = feature_for_preset(&primary_preset)
        && !features.contains(&primary_feature)
    {
        features.push(primary_feature);
    }

    // Python services already provide the HTTP server role, so keep the spec
    // simpler by rendering a single app service instead of a redundant pair.
    if features.contains(&ScaffoldFeature::Python) {
        features.retain(|feature| *feature != ScaffoldFeature::Http);
    }

    GeneratedTemplateSpec {
        primary_preset,
        features,
        http_port: Some(default_http_port()),
        health_path: Some(default_health_path().to_string()),
        worker_interval_secs: Some(default_worker_interval_secs()),
        python_entrypoint: Some(default_python_entrypoint().to_string()),
    }
}

fn prompt_generated_template(
    name: &str,
    preset: Option<&str>,
    prompt: &str,
) -> Result<PromptGenerationResult> {
    if let Some(config) = llm_generation_config_from_env()? {
        let plan = generate_spec_with_llm(&config, name, preset, prompt)?;
        Ok(PromptGenerationResult {
            spec: plan.spec,
            details: PromptGenerationDetails {
                generation_mode: "llm".to_string(),
                provider: Some(config.provider.as_str().to_string()),
                model: Some(config.model),
                summary: Some(plan.summary),
                notes: plan.notes,
            },
        })
    } else {
        Ok(PromptGenerationResult {
            spec: generated_template_spec(preset, prompt),
            details: PromptGenerationDetails {
                generation_mode: "heuristic".to_string(),
                provider: None,
                model: None,
                summary: Some(
                    "No hosted or local LLM provider configured; used built-in prompt planner."
                        .to_string(),
                ),
                notes: vec![],
            },
        })
    }
}

impl LlmProvider {
    fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Local => "local",
        }
    }
}

fn llm_generation_config_from_env() -> Result<Option<LlmGenerationConfig>> {
    let provider = std::env::var("MVM_TEMPLATE_PROVIDER")
        .unwrap_or_else(|_| "auto".to_string())
        .to_ascii_lowercase();

    match provider.as_str() {
        // auto: try local first (probe Ollama / llama.cpp on loopback),
        // then fall through to OpenAI if a key is configured. The order
        // flip lets users with a local model running get sane defaults
        // without having to also set MVM_TEMPLATE_PROVIDER=local.
        "auto" => {
            if let Some(config) = local_generation_config_with_probe() {
                Ok(Some(config))
            } else if let Some(config) = openai_generation_config_from_env() {
                Ok(Some(config))
            } else {
                Ok(None)
            }
        }
        "openai" => Ok(Some(openai_generation_config_from_env().context(
            "MVM_TEMPLATE_PROVIDER=openai requires OPENAI_API_KEY to be set",
        )?)),
        "local" => Ok(Some(local_generation_config_from_env().context(
            "MVM_TEMPLATE_PROVIDER=local requires a local model or base URL",
        )?)),
        "heuristic" => Ok(None),
        other => anyhow::bail!(
            "Unsupported MVM_TEMPLATE_PROVIDER {:?}. Valid values: auto, openai, local, heuristic",
            other
        ),
    }
}

fn openai_generation_config_from_env() -> Option<LlmGenerationConfig> {
    let api_key = std::env::var("OPENAI_API_KEY").ok()?;
    let base_url = std::env::var("MVM_TEMPLATE_OPENAI_BASE_URL")
        .or_else(|_| std::env::var("OPENAI_BASE_URL"))
        .unwrap_or_else(|_| "https://api.openai.com".to_string());
    let model =
        std::env::var("MVM_TEMPLATE_OPENAI_MODEL").unwrap_or_else(|_| "gpt-5.2".to_string());
    Some(LlmGenerationConfig {
        provider: LlmProvider::OpenAi,
        api_key: Some(api_key),
        base_url,
        model,
    })
}

fn local_generation_config_from_env() -> Option<LlmGenerationConfig> {
    let base_url = std::env::var("MVM_TEMPLATE_LOCAL_BASE_URL")
        .ok()
        .or_else(|| std::env::var("LOCALAI_BASE_URL").ok())?;
    let model = std::env::var("MVM_TEMPLATE_LOCAL_MODEL")
        .ok()
        .or_else(|| std::env::var("LOCALAI_MODEL").ok())
        .unwrap_or_else(|| "qwen2.5-coder-7b-instruct".to_string());
    let api_key = std::env::var("MVM_TEMPLATE_LOCAL_API_KEY")
        .ok()
        .or_else(|| std::env::var("LOCALAI_API_KEY").ok());
    Some(LlmGenerationConfig {
        provider: LlmProvider::Local,
        api_key,
        base_url,
        model,
    })
}

/// Default loopback targets probed for an OpenAI-compatible local endpoint
/// when neither `MVM_TEMPLATE_LOCAL_BASE_URL` nor `LOCALAI_BASE_URL` is set.
const DEFAULT_LOCAL_PROBE_TARGETS: &[&str] = &["http://127.0.0.1:11434", "http://127.0.0.1:8080"];

/// Try to discover a running local OpenAI-compatible endpoint on loopback.
///
/// Returns a [`LlmGenerationConfig`] when one of the probe targets responds
/// to `GET /v1/models` within ~200ms; otherwise `None`. The escape hatch
/// `MVM_TEMPLATE_NO_LOCAL_PROBE=1` skips the probe entirely (used in CI
/// or sandboxed environments where loopback connects can hang).
fn local_generation_config_with_probe() -> Option<LlmGenerationConfig> {
    if let Some(config) = local_generation_config_from_env() {
        return Some(config);
    }
    if std::env::var_os("MVM_TEMPLATE_NO_LOCAL_PROBE").is_some() {
        return None;
    }
    let base_url = probe_local_openai_endpoint()?;
    let model = std::env::var("MVM_TEMPLATE_LOCAL_MODEL")
        .ok()
        .or_else(|| std::env::var("LOCALAI_MODEL").ok())
        .unwrap_or_else(|| "qwen2.5-coder-7b-instruct".to_string());
    let api_key = std::env::var("MVM_TEMPLATE_LOCAL_API_KEY")
        .ok()
        .or_else(|| std::env::var("LOCALAI_API_KEY").ok());
    Some(LlmGenerationConfig {
        provider: LlmProvider::Local,
        api_key,
        base_url,
        model,
    })
}

/// Probe each candidate base URL for an OpenAI-compatible `/v1/models`
/// endpoint. Returns the first one that responds with 2xx within 200ms.
fn probe_local_openai_endpoint() -> Option<String> {
    let targets_env = std::env::var("MVM_TEMPLATE_LOCAL_PROBE_TARGETS").ok();
    let owned: Vec<String> = match targets_env.as_deref() {
        Some(s) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        None => DEFAULT_LOCAL_PROBE_TARGETS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .ok()?;
    for base in owned {
        let endpoint = format!("{}/v1/models", base.trim_end_matches('/'));
        if let Ok(resp) = client.get(&endpoint).send()
            && resp.status().is_success()
        {
            return Some(base);
        }
    }
    None
}

fn generate_spec_with_llm(
    config: &LlmGenerationConfig,
    name: &str,
    preset: Option<&str>,
    prompt: &str,
) -> Result<ValidatedOpenAiPlan> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("mvmctl/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .build()
        .context("Failed to build OpenAI HTTP client")?;
    let endpoint = format!("{}/v1/responses", config.base_url.trim_end_matches('/'));
    let request = build_openai_prompt_request(&config.model, name, preset, prompt);
    let mut request_builder = client
        .post(&endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json");
    if let Some(api_key) = config.api_key.as_ref() {
        request_builder = request_builder.header("Authorization", format!("Bearer {}", api_key));
    }
    let response = request_builder
        .json(&request)
        .send()
        .with_context(|| format!("{} request failed: {}", config.provider.as_str(), endpoint))?;

    let status = response.status();
    let body = response
        .text()
        .with_context(|| format!("Failed to read LLM response body from {}", endpoint))?;
    if !status.is_success() {
        anyhow::bail!(
            "{} template planning failed with HTTP {}: {}",
            config.provider.as_str(),
            status,
            body
        );
    }

    let plan = parse_openai_prompt_response(&body)?;
    validate_openai_plan(plan, preset)
}

fn feature_for_preset(preset: &str) -> Option<ScaffoldFeature> {
    match preset {
        "minimal" => None,
        "python" => Some(ScaffoldFeature::Python),
        "http" => Some(ScaffoldFeature::Http),
        "postgres" => Some(ScaffoldFeature::Postgres),
        "worker" => Some(ScaffoldFeature::Worker),
        _ => None,
    }
}

fn resolve_scaffold_preset(preset: Option<&str>, prompt: Option<&str>) -> String {
    preset
        .map(ToOwned::to_owned)
        .or_else(|| prompt.map(infer_prompt_preset))
        .unwrap_or_else(|| "minimal".to_string())
}

fn infer_prompt_preset(prompt: &str) -> String {
    let lower = prompt.to_ascii_lowercase();
    if lower.contains("python")
        || lower.contains("fastapi")
        || lower.contains("flask")
        || lower.contains("django")
    {
        "python".to_string()
    } else if lower.contains("worker")
        || lower.contains("queue")
        || lower.contains("cron")
        || lower.contains("job")
        || lower.contains("poll")
    {
        "worker".to_string()
    } else if lower.contains("http")
        || lower.contains("web")
        || lower.contains("api")
        || lower.contains("server")
    {
        "http".to_string()
    } else if lower.contains("postgres")
        || lower.contains("postgresql")
        || lower.contains("database")
    {
        "postgres".to_string()
    } else {
        "minimal".to_string()
    }
}

fn infer_prompt_features(prompt: &str) -> Vec<ScaffoldFeature> {
    let lower = prompt.to_ascii_lowercase();
    let mut features = Vec::new();

    if lower.contains("python")
        || lower.contains("fastapi")
        || lower.contains("flask")
        || lower.contains("django")
    {
        features.push(ScaffoldFeature::Python);
    }

    if lower.contains("http")
        || lower.contains("web")
        || lower.contains("api")
        || lower.contains("server")
    {
        features.push(ScaffoldFeature::Http);
    }

    if lower.contains("postgres") || lower.contains("postgresql") || lower.contains("database") {
        features.push(ScaffoldFeature::Postgres);
    }

    if lower.contains("worker")
        || lower.contains("queue")
        || lower.contains("cron")
        || lower.contains("job")
        || lower.contains("poll")
    {
        features.push(ScaffoldFeature::Worker);
    }

    features
}

fn build_openai_prompt_request(
    model: &str,
    name: &str,
    preset: Option<&str>,
    prompt: &str,
) -> serde_json::Value {
    let preset_hint = preset.unwrap_or("none");
    serde_json::json!({
        "model": model,
        "input": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "input_text",
                        "text": "You generate safe microVM scaffold plans for mvmctl. Output only schema-compliant JSON. Keep plans constrained to supported presets and features. Never emit secrets, host paths, shell substitutions, or arbitrary package names."
                    }
                ]
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": format!(
                            "Template name: {name}\nExplicit preset override: {preset_hint}\nPrompt: {prompt}\n\nChoose primary_preset from minimal/http/postgres/worker/python. Features may include python/http/postgres/worker. Use only safe defaults: port 8080 unless the workload strongly implies another HTTP port, health_path should start with '/', worker_interval_secs should be 1-3600, python_entrypoint should be a relative file path like main.py. Prefer python over plain http when the prompt is Python-specific. Prefer app/runtime presets over backing services."
                        )
                    }
                ]
            }
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "mvm_template_plan",
                "strict": true,
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "schema_version": { "type": "integer", "enum": [1] },
                        "summary": { "type": "string" },
                        "primary_preset": {
                            "type": "string",
                            "enum": ["minimal", "http", "postgres", "worker", "python"]
                        },
                        "features": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["python", "http", "postgres", "worker"]
                            },
                            "uniqueItems": true
                        },
                        "http_port": {
                            "anyOf": [
                                { "type": "integer", "minimum": 1, "maximum": 65535 },
                                { "type": "null" }
                            ]
                        },
                        "health_path": {
                            "anyOf": [
                                { "type": "string" },
                                { "type": "null" }
                            ]
                        },
                        "worker_interval_secs": {
                            "anyOf": [
                                { "type": "integer", "minimum": 1, "maximum": 3600 },
                                { "type": "null" }
                            ]
                        },
                        "python_entrypoint": {
                            "anyOf": [
                                { "type": "string" },
                                { "type": "null" }
                            ]
                        },
                        "notes": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    },
                    "required": [
                        "schema_version",
                        "summary",
                        "primary_preset",
                        "features",
                        "http_port",
                        "health_path",
                        "worker_interval_secs",
                        "python_entrypoint",
                        "notes"
                    ]
                }
            }
        }
    })
}

fn parse_openai_prompt_response(body: &str) -> Result<OpenAiTemplatePlan> {
    let response: serde_json::Value =
        serde_json::from_str(body).context("Failed to parse OpenAI JSON response")?;

    if let Some(output_text) = response
        .get("output_text")
        .and_then(serde_json::Value::as_str)
    {
        return serde_json::from_str(output_text)
            .context("Failed to parse JSON plan from OpenAI output_text");
    }

    let output = response
        .get("output")
        .and_then(serde_json::Value::as_array)
        .context("OpenAI response missing output array")?;
    for item in output {
        if let Some(content) = item.get("content").and_then(serde_json::Value::as_array) {
            for part in content {
                if part.get("type").and_then(serde_json::Value::as_str) == Some("output_text")
                    && let Some(text) = part.get("text").and_then(serde_json::Value::as_str)
                {
                    return serde_json::from_str(text)
                        .context("Failed to parse JSON plan from OpenAI output content");
                }
            }
        }
    }

    anyhow::bail!("OpenAI response did not include structured output text")
}

fn validate_openai_plan(
    plan: OpenAiTemplatePlan,
    preset: Option<&str>,
) -> Result<ValidatedOpenAiPlan> {
    if plan.schema_version != 1 {
        anyhow::bail!(
            "Unsupported OpenAI template plan schema: {}",
            plan.schema_version
        );
    }

    let mut features = Vec::new();
    for feature in plan.features {
        let parsed = parse_feature_name(&feature)
            .with_context(|| format!("OpenAI returned unsupported feature {:?}", feature))?;
        if !features.contains(&parsed) {
            features.push(parsed);
        }
    }

    let primary_preset = resolve_scaffold_preset(preset, Some(&plan.primary_preset));
    if let Some(primary_feature) = feature_for_preset(&primary_preset)
        && !features.contains(&primary_feature)
    {
        features.push(primary_feature);
    }
    if features.contains(&ScaffoldFeature::Python) {
        features.retain(|feature| *feature != ScaffoldFeature::Http);
    }

    let health_path = validate_health_path(plan.health_path)?;
    let python_entrypoint = validate_python_entrypoint(plan.python_entrypoint)?;
    let worker_interval_secs = plan.worker_interval_secs.map(|secs| secs.clamp(1, 3600));
    let http_port = if features.contains(&ScaffoldFeature::Python)
        || features.contains(&ScaffoldFeature::Http)
    {
        Some(plan.http_port.unwrap_or(default_http_port()))
    } else {
        None
    };

    Ok(ValidatedOpenAiPlan {
        spec: GeneratedTemplateSpec {
            primary_preset,
            features,
            http_port,
            health_path,
            worker_interval_secs,
            python_entrypoint,
        },
        summary: plan.summary,
        notes: plan.notes,
    })
}

fn parse_feature_name(value: &str) -> Result<ScaffoldFeature> {
    match value {
        "python" => Ok(ScaffoldFeature::Python),
        "http" => Ok(ScaffoldFeature::Http),
        "postgres" => Ok(ScaffoldFeature::Postgres),
        "worker" => Ok(ScaffoldFeature::Worker),
        other => anyhow::bail!("unsupported feature {:?}", other),
    }
}

fn validate_health_path(path: Option<String>) -> Result<Option<String>> {
    match path {
        Some(path) if path.starts_with('/') => Ok(Some(path)),
        Some(path) => anyhow::bail!("health_path must start with '/': {}", path),
        None => Ok(Some(default_health_path().to_string())),
    }
}

fn validate_python_entrypoint(path: Option<String>) -> Result<Option<String>> {
    match path {
        Some(path)
            if !path.is_empty()
                && !path.starts_with('/')
                && path.chars().all(|ch| {
                    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/')
                }) =>
        {
            Ok(Some(path))
        }
        Some(path) => anyhow::bail!("invalid python_entrypoint {:?}", path),
        None => Ok(Some(default_python_entrypoint().to_string())),
    }
}

fn default_http_port() -> u16 {
    8080
}

fn default_health_path() -> &'static str {
    "/"
}

fn default_worker_interval_secs() -> u32 {
    10
}

fn default_python_entrypoint() -> &'static str {
    "main.py"
}

fn render_prompt_generated_flake(name: &str, spec: &GeneratedTemplateSpec) -> String {
    let http_port = spec.http_port.unwrap_or(default_http_port());
    let health_path = spec.health_path.as_deref().unwrap_or(default_health_path());
    let worker_interval_secs = spec
        .worker_interval_secs
        .unwrap_or(default_worker_interval_secs());
    let python_entrypoint = spec
        .python_entrypoint
        .as_deref()
        .unwrap_or(default_python_entrypoint());

    let mut let_lines = vec![
        "      system = \"aarch64-linux\"; # change to x86_64-linux if needed".to_string(),
        "      pkgs = import nixpkgs { inherit system; };".to_string(),
    ];

    if spec.features.contains(&ScaffoldFeature::Postgres) {
        let_lines.push("      pgData = \"/var/lib/postgresql/data\";".to_string());
    }

    if spec.features.contains(&ScaffoldFeature::Python) {
        let_lines.push(String::new());
        let_lines.push("      # Python with dependencies from nixpkgs.".to_string());
        let_lines.push(
            "      # Add packages to the list: ps.fastapi, ps.flask, ps.requests, etc.".to_string(),
        );
        let_lines.push("      python = pkgs.python3.withPackages (ps: [".to_string());
        let_lines.push("        # ps.fastapi".to_string());
        let_lines.push("        # ps.uvicorn".to_string());
        let_lines.push("      ]);".to_string());
        let_lines.push(String::new());
        let_lines.push("      appSrc = pkgs.stdenv.mkDerivation {".to_string());
        let_lines.push(format!("        pname = \"{name}-app\";"));
        let_lines.push("        version = \"0\";".to_string());
        let_lines.push("        src = ./app;".to_string());
        let_lines.push("        installPhase = \"cp -r . $out\";".to_string());
        let_lines.push("      };".to_string());
    }

    let mut package_items: Vec<&str> = Vec::new();
    if spec.features.contains(&ScaffoldFeature::Python) {
        package_items.extend(["python", "appSrc"]);
    }
    if spec.features.contains(&ScaffoldFeature::Postgres) {
        package_items.push("pkgs.postgresql");
    }
    if spec.features.contains(&ScaffoldFeature::Worker) {
        package_items.extend(["pkgs.bash", "pkgs.coreutils"]);
    }
    if spec.features.contains(&ScaffoldFeature::Http)
        && !spec.features.contains(&ScaffoldFeature::Python)
    {
        package_items.push("pkgs.python3");
    }
    if spec.features.is_empty() {
        package_items.extend(["pkgs.curl", "pkgs.bash"]);
    } else if spec.features.contains(&ScaffoldFeature::Python)
        || spec.features.contains(&ScaffoldFeature::Http)
        || spec.features.contains(&ScaffoldFeature::Postgres)
    {
        package_items.push("pkgs.curl");
    }

    let mut packages = Vec::new();
    for item in package_items {
        if !packages.contains(&item) {
            packages.push(item);
        }
    }

    let mut service_entries = Vec::new();
    let mut health_entries = Vec::new();

    if spec.features.contains(&ScaffoldFeature::Python) {
        service_entries.push(format!(
            "        services.app = {{\n          command = \"${{python}}/bin/python3 ${{appSrc}}/{python_entrypoint}\";\n          env = {{\n            PORT = \"{http_port}\";\n            PYTHONUNBUFFERED = \"1\";\n          }};\n        }};"
        ));
        health_entries.push(format!(
            "        healthChecks.app = {{\n          healthCmd = \"${{pkgs.curl}}/bin/curl -sf http://localhost:{http_port}{health_path} >/dev/null\";\n          healthIntervalSecs = 5;\n          healthTimeoutSecs = 3;\n        }};"
        ));
    } else if spec.features.contains(&ScaffoldFeature::Http) {
        service_entries.push(format!(
            "        services.web = {{\n          command = \"${{pkgs.python3}}/bin/python3 -m http.server {http_port}\";\n        }};"
        ));
        health_entries.push(format!(
            "        healthChecks.web = {{\n          healthCmd = \"${{pkgs.curl}}/bin/curl -sf http://localhost:{http_port}{health_path} >/dev/null\";\n          healthIntervalSecs = 5;\n          healthTimeoutSecs = 3;\n        }};"
        ));
    }

    if spec.features.contains(&ScaffoldFeature::Postgres) {
        service_entries.push(
            r#"        services.postgres = {
          preStart = ''
            if [ ! -f ${pgData}/PG_VERSION ]; then
              mkdir -p ${pgData}
              chown postgres:postgres ${pgData}
              su -s /bin/sh postgres -c "${pkgs.postgresql}/bin/initdb -D ${pgData}"
            fi
          '';
          command = "${pkgs.postgresql}/bin/postgres -D ${pgData} -k /run/postgresql";
        };"#
            .to_string(),
        );
        health_entries.push(
            r#"        healthChecks.postgres = {
          healthCmd = "${pkgs.postgresql}/bin/pg_isready -h localhost";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 5;
        };"#
            .to_string(),
        );
    }

    if spec.features.contains(&ScaffoldFeature::Worker) {
        service_entries.push(format!(
            "        services.worker = {{\n          preStart = \"mkdir -p /run/worker\";\n          command = \"${{pkgs.bash}}/bin/bash -c 'while true; do echo \\\"[worker] tick $(date)\\\"; touch /run/worker/healthy; sleep {worker_interval_secs}; done'\";\n        }};"
        ));
        health_entries.push(format!(
            "        healthChecks.worker = {{\n          healthCmd = \"${{pkgs.bash}}/bin/bash -c 'test -f /run/worker/healthy'\";\n          healthIntervalSecs = {worker_interval_secs};\n          healthTimeoutSecs = 5;\n        }};"
        ));
    }

    let mut body_lines = vec![format!("        name = \"{name}\";"), String::new()];
    body_lines.push(format!("        packages = [ {} ];", packages.join(" ")));

    if !service_entries.is_empty() {
        body_lines.push(String::new());
        body_lines
            .push("        # Generated service definitions inferred from the prompt.".to_string());
        body_lines.extend(service_entries.into_iter().flat_map(|entry| {
            let mut lines: Vec<String> = entry.lines().map(ToOwned::to_owned).collect();
            lines.push(String::new());
            lines
        }));
        body_lines.pop();
    } else {
        body_lines.push(String::new());
        body_lines.push("        # Add supervised services here.".to_string());
    }

    if !health_entries.is_empty() {
        body_lines.push(String::new());
        body_lines.push("        # Generated health checks inferred from the prompt.".to_string());
        body_lines.extend(health_entries.into_iter().flat_map(|entry| {
            let mut lines: Vec<String> = entry.lines().map(ToOwned::to_owned).collect();
            lines.push(String::new());
            lines
        }));
        body_lines.pop();
    }

    format!(
        "{{\n  description = \"mvm microVM — {} prompt scaffold\";\n\n  inputs = {{\n    mvm.url = \"github:auser/mvm?dir=nix\";\n    nixpkgs.url = \"github:NixOS/nixpkgs/nixos-25.11\";\n  }};\n\n  outputs = {{ mvm, nixpkgs, ... }}:\n    let\n{}\n    in {{\n      packages.${{system}}.default = mvm.lib.${{system}}.mkGuest {{\n{}\n      }};\n    }};\n}}\n",
        spec.primary_preset,
        let_lines.join("\n"),
        body_lines.join("\n")
    )
}

#[derive(serde::Serialize)]
struct PromptMetadata {
    schema_version: u8,
    template_name: String,
    prompt: String,
    generation_mode: String,
    provider: Option<String>,
    model: Option<String>,
    summary: Option<String>,
    notes: Vec<String>,
    primary_preset: String,
    inferred_features: Vec<&'static str>,
    http_port: Option<u16>,
    health_path: Option<String>,
    worker_interval_secs: Option<u32>,
    python_entrypoint: Option<String>,
    created_at: String,
}

fn scaffold_template_files(
    dir: &Path,
    name: &str,
    preset: &str,
    prompt: Option<&str>,
) -> Result<()> {
    fs::create_dir_all(dir)?;
    let prompt_result = prompt
        .map(|prompt| prompt_generated_template(name, Some(preset), prompt))
        .transpose()?;

    let gitignore = dir.join(".gitignore");
    if !gitignore.exists() {
        fs::write(
            &gitignore,
            include_str!("../resources/template_scaffold/.gitignore"),
        )?;
    }

    let flake_path = dir.join("flake.nix");
    if !flake_path.exists() {
        let flake = if let Some(result) = prompt_result.as_ref() {
            render_prompt_generated_flake(name, &result.spec)
        } else {
            flake_content_for_preset(preset)?.to_string()
        };
        fs::write(&flake_path, flake)?;
    }

    let readme_path = dir.join("README.md");
    if !readme_path.exists() {
        let content =
            include_str!("../resources/template_scaffold/README.md").replace("{{name}}", name);
        fs::write(&readme_path, content)?;
    }

    if let Some(result) = prompt_result.as_ref() {
        scaffold_prompt_support_files(dir, &result.spec)?;
    }

    if let (Some(prompt), Some(result)) = (prompt, prompt_result.as_ref()) {
        let prompt_path = dir.join("mvm-template-prompt.json");
        if !prompt_path.exists() {
            let metadata = PromptMetadata {
                schema_version: 3,
                template_name: name.to_string(),
                prompt: prompt.to_string(),
                generation_mode: result.details.generation_mode.clone(),
                provider: result.details.provider.clone(),
                model: result.details.model.clone(),
                summary: result.details.summary.clone(),
                notes: result.details.notes.clone(),
                primary_preset: result.spec.primary_preset.clone(),
                inferred_features: result
                    .spec
                    .features
                    .iter()
                    .copied()
                    .map(ScaffoldFeature::as_str)
                    .collect(),
                http_port: result.spec.http_port,
                health_path: result.spec.health_path.clone(),
                worker_interval_secs: result.spec.worker_interval_secs,
                python_entrypoint: result.spec.python_entrypoint.clone(),
                created_at: now_iso(),
            };
            fs::write(&prompt_path, serde_json::to_string_pretty(&metadata)?)?;
        }
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

fn scaffold_prompt_support_files(dir: &Path, spec: &GeneratedTemplateSpec) -> Result<()> {
    if spec.features.contains(&ScaffoldFeature::Python) {
        let entrypoint = spec
            .python_entrypoint
            .as_deref()
            .unwrap_or(default_python_entrypoint());
        let app_path = dir.join("app").join(entrypoint);
        if !app_path.exists() {
            if let Some(parent) = app_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(
                &app_path,
                render_python_app_stub(
                    spec.http_port.unwrap_or(default_http_port()),
                    spec.health_path.as_deref().unwrap_or(default_health_path()),
                ),
            )?;
        }
    }
    Ok(())
}

fn render_python_app_stub(port: u16, health_path: &str) -> String {
    format!(
        "import os\nfrom http.server import BaseHTTPRequestHandler, HTTPServer\n\nPORT = int(os.environ.get(\"PORT\", \"{port}\"))\nHEALTH_PATH = \"{health_path}\"\n\n\nclass Handler(BaseHTTPRequestHandler):\n    def do_GET(self):\n        if self.path in (\"/\", HEALTH_PATH):\n            self.send_response(200)\n            self.send_header(\"Content-Type\", \"text/plain; charset=utf-8\")\n            self.end_headers()\n            self.wfile.write(b\"ok\\n\")\n            return\n        self.send_response(404)\n        self.end_headers()\n\n\nif __name__ == \"__main__\":\n    server = HTTPServer((\"0.0.0.0\", PORT), Handler)\n    print(f\"listening on {{PORT}}\")\n    server.serve_forever()\n"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        GeneratedTemplateSpec, ScaffoldFeature, build_openai_prompt_request,
        generated_template_spec, infer_prompt_features, infer_prompt_preset,
        parse_openai_prompt_response, render_prompt_generated_flake, resolve_scaffold_preset,
        validate_openai_plan,
    };

    #[test]
    fn test_infer_prompt_preset_python() {
        assert_eq!(
            infer_prompt_preset("Python API worker with FastAPI"),
            "python"
        );
    }

    #[test]
    fn test_infer_prompt_preset_worker() {
        assert_eq!(
            infer_prompt_preset("Background worker that polls an API every minute"),
            "worker"
        );
    }

    #[test]
    fn test_resolve_scaffold_preset_explicit_wins() {
        assert_eq!(
            resolve_scaffold_preset(Some("postgres"), Some("python web app")),
            "postgres"
        );
    }

    #[test]
    fn test_infer_prompt_features_can_merge_python_and_postgres() {
        assert_eq!(
            infer_prompt_features("Python API with PostgreSQL backing store"),
            vec![
                ScaffoldFeature::Python,
                ScaffoldFeature::Http,
                ScaffoldFeature::Postgres
            ]
        );
    }

    #[test]
    fn test_generated_template_spec_deduplicates_http_when_python_present() {
        assert_eq!(
            generated_template_spec(None, "python http api with postgres"),
            GeneratedTemplateSpec {
                primary_preset: "python".to_string(),
                features: vec![ScaffoldFeature::Python, ScaffoldFeature::Postgres],
                http_port: Some(8080),
                health_path: Some("/".to_string()),
                worker_interval_secs: Some(10),
                python_entrypoint: Some("main.py".to_string()),
            }
        );
    }

    #[test]
    fn test_render_prompt_generated_flake_combines_python_and_postgres() {
        let flake = render_prompt_generated_flake(
            "analytics-worker",
            &GeneratedTemplateSpec {
                primary_preset: "python".to_string(),
                features: vec![ScaffoldFeature::Python, ScaffoldFeature::Postgres],
                http_port: Some(9090),
                health_path: Some("/healthz".to_string()),
                worker_interval_secs: Some(10),
                python_entrypoint: Some("server.py".to_string()),
            },
        );
        assert!(flake.contains("services.app"));
        assert!(flake.contains("services.postgres"));
        assert!(flake.contains("pkgs.postgresql"));
        assert!(flake.contains("healthChecks.postgres"));
        assert!(flake.contains("localhost:9090/healthz"));
        assert!(flake.contains("${appSrc}/server.py"));
    }

    #[test]
    fn test_build_openai_prompt_request_uses_json_schema() {
        let request = build_openai_prompt_request("gpt-5.2", "demo", None, "python api");
        assert_eq!(request["model"], "gpt-5.2");
        assert_eq!(request["text"]["format"]["type"], "json_schema");
        assert_eq!(request["text"]["format"]["strict"], true);
    }

    #[test]
    fn test_parse_openai_prompt_response_reads_output_text() {
        let response = r#"{
            "output": [{
                "content": [{
                    "type": "output_text",
                    "text": "{\"schema_version\":1,\"summary\":\"Python API\",\"primary_preset\":\"python\",\"features\":[\"python\",\"postgres\"],\"http_port\":8000,\"health_path\":\"/health\",\"worker_interval_secs\":null,\"python_entrypoint\":\"service.py\",\"notes\":[\"Use python app stub\"]}"
                }]
            }]
        }"#;
        let plan = parse_openai_prompt_response(response).expect("parse plan");
        assert_eq!(plan.primary_preset, "python");
        assert_eq!(plan.http_port, Some(8000));
        assert_eq!(plan.python_entrypoint.as_deref(), Some("service.py"));
    }

    #[test]
    fn test_validate_openai_plan_normalizes_and_merges_features() {
        let validated = validate_openai_plan(
            super::OpenAiTemplatePlan {
                schema_version: 1,
                summary: "Python API with postgres".to_string(),
                primary_preset: "python".to_string(),
                features: vec![
                    "python".to_string(),
                    "http".to_string(),
                    "postgres".to_string(),
                ],
                http_port: Some(8000),
                health_path: Some("/ready".to_string()),
                worker_interval_secs: None,
                python_entrypoint: Some("app.py".to_string()),
                notes: vec!["Keep postgres local".to_string()],
            },
            None,
        )
        .expect("validated plan");
        assert_eq!(
            validated.spec.features,
            vec![ScaffoldFeature::Python, ScaffoldFeature::Postgres]
        );
        assert_eq!(validated.spec.http_port, Some(8000));
        assert_eq!(validated.spec.health_path.as_deref(), Some("/ready"));
        assert_eq!(validated.spec.python_entrypoint.as_deref(), Some("app.py"));
        assert_eq!(validated.summary, "Python API with postgres");
    }

    // ----- Local-LLM probe tests (Proposal C) ---------------------------
    //
    // These tests mutate process-global env vars (MVM_TEMPLATE_*,
    // OPENAI_API_KEY) so they must serialize via probe_test_lock().
    // Each test exercises multiple phases inside one #[test] body so
    // env-state transitions are explicit instead of relying on cargo's
    // parallel scheduler.

    use super::{
        LlmProvider, llm_generation_config_from_env, local_generation_config_with_probe,
        probe_local_openai_endpoint,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Mutex, OnceLock};
    use std::thread;

    fn probe_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Spawn a one-shot TCP server that responds to a single HTTP request
    /// with `200 OK` and the given JSON body. Returns the bound `host:port`.
    fn spawn_one_shot_http_ok(json_body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("addr").to_string();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json_body.len(),
                    json_body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        addr
    }

    /// Restore env vars to a known baseline before/after each probe scenario.
    fn clear_llm_env() {
        // SAFETY: tests serialize via probe_test_lock(); the process is
        // single-threaded with respect to env access while the lock is held.
        unsafe {
            std::env::remove_var("MVM_TEMPLATE_PROVIDER");
            std::env::remove_var("MVM_TEMPLATE_LOCAL_BASE_URL");
            std::env::remove_var("LOCALAI_BASE_URL");
            std::env::remove_var("MVM_TEMPLATE_LOCAL_MODEL");
            std::env::remove_var("LOCALAI_MODEL");
            std::env::remove_var("MVM_TEMPLATE_LOCAL_API_KEY");
            std::env::remove_var("LOCALAI_API_KEY");
            std::env::remove_var("MVM_TEMPLATE_LOCAL_PROBE_TARGETS");
            std::env::remove_var("MVM_TEMPLATE_NO_LOCAL_PROBE");
            std::env::remove_var("OPENAI_API_KEY");
            std::env::remove_var("MVM_TEMPLATE_OPENAI_BASE_URL");
            std::env::remove_var("OPENAI_BASE_URL");
            std::env::remove_var("MVM_TEMPLATE_OPENAI_MODEL");
        }
    }

    #[test]
    fn test_local_probe_scenarios() {
        let _guard = probe_test_lock().lock().unwrap_or_else(|e| e.into_inner());

        // Phase 1: probe target reachable → returns base_url; auto picks Local.
        clear_llm_env();
        let addr = spawn_one_shot_http_ok(r#"{"data":[]}"#);
        let target = format!("http://{}", addr);
        // SAFETY: serialised by probe_test_lock; see clear_llm_env doc.
        unsafe {
            std::env::set_var("MVM_TEMPLATE_LOCAL_PROBE_TARGETS", &target);
        }
        let probed = probe_local_openai_endpoint();
        assert_eq!(probed.as_deref(), Some(target.as_str()));

        // The one-shot server is consumed; respawn for the auto path.
        let addr2 = spawn_one_shot_http_ok(r#"{"data":[]}"#);
        let target2 = format!("http://{}", addr2);
        // SAFETY: serialised by probe_test_lock.
        unsafe {
            std::env::set_var("MVM_TEMPLATE_LOCAL_PROBE_TARGETS", &target2);
        }
        let cfg = llm_generation_config_from_env()
            .expect("auto with probe should not error")
            .expect("auto picks Local when probe succeeds");
        assert_eq!(cfg.provider, LlmProvider::Local);
        assert_eq!(cfg.base_url, target2);

        // Phase 2: probe targets unreachable → falls through to OpenAI.
        clear_llm_env();
        // SAFETY: serialised by probe_test_lock.
        unsafe {
            // Port 1 is privileged + nothing listens; near-instant ECONNREFUSED.
            std::env::set_var("MVM_TEMPLATE_LOCAL_PROBE_TARGETS", "http://127.0.0.1:1");
            std::env::set_var("OPENAI_API_KEY", "test-key-fallthrough");
        }
        let cfg = llm_generation_config_from_env()
            .expect("auto with no local should not error")
            .expect("auto falls through to OpenAI");
        assert_eq!(cfg.provider, LlmProvider::OpenAi);

        // Phase 3: MVM_TEMPLATE_NO_LOCAL_PROBE=1 skips the probe even when
        // a target is reachable. Without OPENAI_API_KEY, auto returns None.
        clear_llm_env();
        let addr3 = spawn_one_shot_http_ok(r#"{"data":[]}"#);
        let target3 = format!("http://{}", addr3);
        // SAFETY: serialised by probe_test_lock.
        unsafe {
            std::env::set_var("MVM_TEMPLATE_LOCAL_PROBE_TARGETS", &target3);
            std::env::set_var("MVM_TEMPLATE_NO_LOCAL_PROBE", "1");
        }
        assert!(local_generation_config_with_probe().is_none());
        let cfg = llm_generation_config_from_env().expect("auto with no probe + no openai");
        assert!(
            cfg.is_none(),
            "no-probe + no OpenAI key → heuristic fallback"
        );

        // Phase 4: explicit MVM_TEMPLATE_LOCAL_BASE_URL bypasses the probe.
        clear_llm_env();
        // SAFETY: serialised by probe_test_lock.
        unsafe {
            // Use a non-listening URL: env-driven path doesn't validate
            // reachability, only the probe path does.
            std::env::set_var("MVM_TEMPLATE_LOCAL_BASE_URL", "http://127.0.0.1:1");
        }
        let cfg =
            local_generation_config_with_probe().expect("env-driven local config skips probe");
        assert_eq!(cfg.provider, LlmProvider::Local);
        assert_eq!(cfg.base_url, "http://127.0.0.1:1");

        clear_llm_env();
    }

    #[test]
    fn test_explicit_provider_modes_unchanged_by_probe() {
        let _guard = probe_test_lock().lock().unwrap_or_else(|e| e.into_inner());

        // explicit "openai" without OPENAI_API_KEY errors; the probe path
        // is not consulted (would otherwise trigger when in `auto`).
        clear_llm_env();
        // SAFETY: serialised by probe_test_lock.
        unsafe {
            std::env::set_var("MVM_TEMPLATE_PROVIDER", "openai");
        }
        let err = llm_generation_config_from_env().unwrap_err();
        assert!(
            format!("{err:#}").contains("OPENAI_API_KEY"),
            "expected OPENAI_API_KEY error, got: {err:#}"
        );

        // explicit "local" without any base_url errors; the probe path
        // is not consulted in `local` mode either.
        clear_llm_env();
        // SAFETY: serialised by probe_test_lock.
        unsafe {
            std::env::set_var("MVM_TEMPLATE_PROVIDER", "local");
        }
        let err = llm_generation_config_from_env().unwrap_err();
        assert!(
            format!("{err:#}").contains("local model"),
            "expected local-mode error, got: {err:#}"
        );

        // "heuristic" returns Ok(None) regardless of env state.
        clear_llm_env();
        // SAFETY: serialised by probe_test_lock.
        unsafe {
            std::env::set_var("MVM_TEMPLATE_PROVIDER", "heuristic");
            std::env::set_var("OPENAI_API_KEY", "ignored");
        }
        let cfg = llm_generation_config_from_env().expect("heuristic always Ok");
        assert!(cfg.is_none());

        clear_llm_env();
    }
}
