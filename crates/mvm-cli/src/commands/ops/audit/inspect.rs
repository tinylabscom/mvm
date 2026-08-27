use anyhow::{Context, Result};
use std::io::BufRead;

use super::{SignedEnvelope, audit_path_for_tenant, default_audit_dir, print_chain_line, ui};

pub(super) fn audit_show(tenant: &str, plan_id: &str, json: bool) -> Result<()> {
    let dir = default_audit_dir()?;
    let path = audit_path_for_tenant(&dir, tenant);
    if !path.exists() {
        if json {
            crate::json_out::emit_json(&Vec::<SignedEnvelope>::new())?;
        } else {
            ui::info(&format!(
                "No audit chain found for tenant '{tenant}' at {}.",
                path.display()
            ));
        }
        return Ok(());
    }
    let file = std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut matched = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Ok(env) = serde_json::from_str::<SignedEnvelope>(&line)
            && env.entry.plan_id.0 == plan_id
        {
            if json {
                matched.push(env);
            } else {
                print_chain_line(&line);
            }
        }
    }
    if json {
        crate::json_out::emit_json(&matched)?;
    } else if matched.is_empty() {
        ui::info(&format!(
            "No audit entries found for plan_id '{plan_id}' in tenant '{tenant}'."
        ));
    }
    Ok(())
}

pub(super) fn audit_tail(lines: usize, follow: bool) -> Result<()> {
    let log_path = mvm_core::audit::default_audit_log();
    let path = std::path::Path::new(&log_path);
    if !path.exists() {
        ui::info(&format!(
            "No audit log found. Events are recorded at {log_path}."
        ));
        return Ok(());
    }
    print_last_n_lines(path, lines)?;
    if !follow {
        return Ok(());
    }
    let mut pos = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !path.exists() {
            continue;
        }
        let new_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if new_len > pos {
            let mut file = std::fs::File::open(path)?;
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(pos))?;
            for line in std::io::BufReader::new(&file).lines() {
                print_audit_line(&line?);
            }
            pos = new_len;
        }
    }
}

fn print_last_n_lines(path: &std::path::Path, n: usize) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let lines: Vec<String> = std::io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .collect();
    for line in &lines[lines.len().saturating_sub(n)..] {
        print_audit_line(line);
    }
    Ok(())
}

fn print_audit_line(line: &str) {
    match serde_json::from_str::<mvm_core::audit::LocalAuditEvent>(line) {
        Ok(event) => {
            let kind = serde_json::to_string(&event.kind)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            let vm = event
                .vm_name
                .as_deref()
                .map(|n| format!("  [{n}]"))
                .unwrap_or_default();
            let detail = event
                .detail
                .as_deref()
                .map(|d| format!("  {d}"))
                .unwrap_or_default();
            println!("{ts}  {kind}{vm}{detail}", ts = event.timestamp);
        }
        Err(_) => println!("{line}"),
    }
}
