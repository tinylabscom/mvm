use anyhow::{Result, anyhow, bail};
use std::collections::BTreeMap;

// NOTE: Builder script templates support only simple `{{ var }}` placeholders.
// Keep script logic in shell and pass pre-rendered values through the context.

fn script_source(name: &str) -> Option<&'static str> {
    match name {
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
    &["run_nix_build_host", "extract_artifacts_host"]
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
        // run_nix_build_host requires more vars than just run_dir.
        let err = render_script("run_nix_build_host", &ctx).unwrap_err();
        let msg = format!("{err:#}");
        eprintln!("{msg}");
        assert!(msg.contains("run_nix_build_host"));
        assert!(msg.contains("missing template variable"));
    }
}
