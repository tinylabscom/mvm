//! Rendering of the pool status report `mvm_client::standby` builds.

use anyhow::Result;

pub(super) fn run_status(json: bool) -> Result<()> {
    let report = mvm_client::standby::pool_status()?;
    if json {
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }
    println!(
        "Supervisor standby pool: {} idle, {} claimed, {} parked, {} dead",
        report.idle, report.claimed, report.parked, report.dead
    );
    for e in &report.standbys {
        let image_tag = e
            .image_sha256
            .as_deref()
            .map(|s| format!(" · image {}", &s[..s.len().min(12)]))
            .unwrap_or_default();
        println!(
            "  {} · {} · {} · {} vcpu / {} MiB · kernel {}{}",
            e.id,
            e.state,
            if e.pid == 0 {
                "saved-state".to_string()
            } else {
                format!("pid {}", e.pid)
            },
            e.vcpus,
            e.mem_mib,
            &e.kernel_sha256[..e.kernel_sha256.len().min(12)],
            image_tag,
        );
    }
    Ok(())
}
