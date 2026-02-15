use anyhow::Result;
use chrono::Utc;
use clap::ValueEnum;

use mvm_core::template::TemplateSpec;

pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub fn make_spec(
    name: &str,
    flake: &str,
    profile: &str,
    role: &str,
    cpus: u8,
    mem: u32,
    data_disk: u32,
) -> TemplateSpec {
    let ts = now_iso();
    TemplateSpec {
        template_id: name.to_string(),
        flake_ref: flake.to_string(),
        profile: profile.to_string(),
        role: role.to_string(),
        vcpus: cpus,
        mem_mib: mem,
        data_disk_mib: data_disk,
        created_at: ts.clone(),
        updated_at: ts,
    }
}

pub enum TemplateFormat {
    Table,
    Json,
}

impl From<bool> for TemplateFormat {
    fn from(json: bool) -> Self {
        if json {
            TemplateFormat::Json
        } else {
            TemplateFormat::Table
        }
    }
}
