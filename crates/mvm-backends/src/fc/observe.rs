//! Slot allocation/reservation bookkeeping.
//!
//! Workload output is read through `mvm_core::stream_client`, not here.

use anyhow::Result;

use mvm_vmm::host::config::VmSlot;
use mvm_vmm::host::shell::{run_in_vm, run_in_vm_stdout, shell_quote};

use super::abs_vms_dir;

fn allocate_slot_script(vms_dir: &str, name: &str, json_name: &str) -> String {
    format!(
        r#"
        set -e
        mkdir -p {dir}
        (
          flock -x 9
          used="$(
            for f in {dir}/*/run-info.json; do
              [ -f "$f" ] || continue
              sed -n 's/.*"slot_index":\([0-9][0-9]*\).*/\1/p' "$f"
            done 2>/dev/null || true
          )"
          for i in $(seq 0 252); do
            if ! printf '%s\n' "$used" | grep -qx "$i"; then
              vm_dir={dir}/{name}
              mkdir -p "$vm_dir"
              printf '{{"schema_version":1,"mode":"starting","name":%s,"slot_index":%s,"slot_reserved":true}}\n' {json_name} "$i" > "$vm_dir/run-info.json"
              echo "$i"
              exit 0
            fi
          done
          exit 2
        ) 9>{dir}/.slot.lock
        "#,
        dir = shell_quote(vms_dir),
        name = shell_quote(name),
        json_name = shell_quote(json_name),
    )
}

/// Allocate the next free slot index by scanning existing VMs.
pub fn allocate_slot(name: &str) -> Result<VmSlot> {
    let json_name = serde_json::to_string(name)?;
    let output = run_in_vm_stdout(&allocate_slot_script(&abs_vms_dir(), name, &json_name))?;

    let index = output
        .lines()
        .rev()
        .find_map(|line| line.trim().parse::<u8>().ok())
        .ok_or_else(|| anyhow::anyhow!("No free VM slots available (max 253 VMs)"))?;
    Ok(VmSlot::new(name, index))
}

fn release_reservation_script(vms_dir: &str, name: &str) -> String {
    format!(
        r#"
        run_info={dir}/{name}/run-info.json
        if [ -f "$run_info" ] && grep -q '"slot_reserved":true' "$run_info"; then
          rm -f "$run_info"
        fi
        "#,
        dir = shell_quote(vms_dir),
        name = shell_quote(name),
    )
}

pub(super) fn release_slot_reservation(slot: &VmSlot) -> Result<()> {
    run_in_vm(&release_reservation_script(&abs_vms_dir(), &slot.name)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_scripts_quote_directory_and_name_as_single_words() {
        for hostile in [
            "/path with spaces",
            "/path'; touch /tmp/PWN; '",
            "/path$(echo PWN)",
        ] {
            let quoted = shell_quote(hostile);
            let json_name = shell_quote(&serde_json::to_string(hostile).unwrap());
            for (script, extra_quoted) in [
                (allocate_slot_script(hostile, "safe", "\"safe\""), None),
                (
                    allocate_slot_script(
                        "/safe",
                        hostile,
                        &serde_json::to_string(hostile).unwrap(),
                    ),
                    Some(json_name.as_str()),
                ),
                (release_reservation_script(hostile, "safe"), None),
                (release_reservation_script("/safe", hostile), None),
            ] {
                assert!(script.contains(&quoted), "{hostile:?} not quoted: {script}");
                let script = script.replace(&quoted, "Q");
                let script = extra_quoted.map_or(script.clone(), |word| script.replace(word, "Q"));
                assert!(
                    !script.contains("PWN"),
                    "{hostile:?} leaks outside quotes: {script}"
                );
            }
        }
    }
}
