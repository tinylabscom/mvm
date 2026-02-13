use anyhow::Result;

use crate::ui;
use mvm_core::config::fc_version;
use mvm_core::platform;
use mvm_runtime::shell;

#[derive(Debug)]
struct Check {
    name: &'static str,
    cmd: &'static str,
    ok: bool,
    info: String,
}

pub fn run() -> Result<()> {
    let mut checks = Vec::new();

    // Host tools
    checks.push(check_cmd("rustup", "rustup --version"));
    checks.push(check_cmd("cargo", "cargo --version"));
    checks.push(check_cmd("limactl", "limactl --version"));

    // Inside VM tools (if available)
    let in_vm = platform::current().needs_lima();
    if in_vm {
        checks.push(check_vm_cmd("nix", "nix --version"));
        checks.push(check_vm_cmd("firecracker", "firecracker --version"));
    } else {
        checks.push(check_cmd("firecracker", "firecracker --version"));
    }

    // Firecracker version target
    checks.push(Check {
        name: "fc target",
        cmd: "env",
        ok: true,
        info: fc_version(),
    });

    // Render
    ui::status_header();
    for c in &checks {
        let status = if c.ok { "OK" } else { "MISSING" };
        ui::status_line(&format!("{}:", c.name), &format!("{} ({})", status, c.info));
    }

    let missing: Vec<&Check> = checks.iter().filter(|c| !c.ok).collect();
    if !missing.is_empty() {
        ui::warn("Some dependencies are missing. Install them and re-run:");
        for m in missing {
            ui::info(&format!("  {} -> {}", m.name, m.cmd));
        }
        anyhow::bail!("doctor found missing dependencies");
    }

    ui::success("All required tools present.");
    Ok(())
}

fn check_cmd(name: &'static str, cmd: &'static str) -> Check {
    match shell::run_host("bash", &["-lc", cmd]) {
        Ok(out) if out.status.success() => Check {
            name,
            cmd,
            ok: true,
            info: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        },
        Ok(out) => Check {
            name,
            cmd,
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name,
            cmd,
            ok: false,
            info: e.to_string(),
        },
    }
}

fn check_vm_cmd(name: &'static str, cmd: &'static str) -> Check {
    match shell::run_on_vm("mvm", cmd) {
        Ok(out) if out.status.success() => Check {
            name,
            cmd,
            ok: true,
            info: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        },
        Ok(out) => Check {
            name,
            cmd,
            ok: false,
            info: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        },
        Err(e) => Check {
            name,
            cmd,
            ok: false,
            info: e.to_string(),
        },
    }
}
