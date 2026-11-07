//! Slot allocation/reservation bookkeeping.
//!
//! Workload output is read through `mvm_core::stream_client`, not here.

use anyhow::Result;

use mvm_vmm::host::config::VmSlot;
use mvm_vmm::host::shell::{run_in_vm, run_in_vm_stdout, shell_quote};

use super::abs_vms_dir;

/// Allocate the next free slot index by scanning existing VMs.
pub fn allocate_slot(name: &str) -> Result<VmSlot> {
    let q_name = shell_quote(name);
    let q_json_name = shell_quote(&serde_json::to_string(name)?);
    let output = run_in_vm_stdout(&format!(
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
        dir = abs_vms_dir(),
        name = q_name,
        json_name = q_json_name,
    ))?;

    let index = output
        .lines()
        .rev()
        .find_map(|line| line.trim().parse::<u8>().ok())
        .ok_or_else(|| anyhow::anyhow!("No free VM slots available (max 253 VMs)"))?;
    Ok(VmSlot::new(name, index))
}

pub(super) fn release_slot_reservation(slot: &VmSlot) -> Result<()> {
    let q_name = shell_quote(&slot.name);
    run_in_vm(&format!(
        r#"
        run_info={dir}/{name}/run-info.json
        if [ -f {run_info} ] && grep -q '"slot_reserved":true' {run_info}; then
          rm -f {run_info}
        fi
        "#,
        dir = abs_vms_dir(),
        name = q_name,
        run_info = "$run_info",
    ))
    .map(|_| ())
}
