set working-directory := "../.."

# Build the dm-verity-capable workload kernel into the local mvm cache.
# Set MVM_KERNEL_SOURCE=download to use the hash-verified release artifact, or

# MVM_KERNEL_SOURCE=auto to prefer it and compile when no asset is available.
workload:
    cargo run -- kernel build --which workload

# Live Apple-Silicon HVF proof of NIC-less guest runtime and production
# FlowMux HTTPS admit/deny behavior for OCI --allow-host.
hvf-oci-smoke:
    bash scripts/check-hvf-oci-allow-host-smoke.sh

# Live Apple-Silicon HVF warm-restore matrix. Requires the HVF warm capability

# to have passed its live continuity gate; it never enables that capability.
hvf-warm-restore:
    bash scripts/check-hvf-warm-restore.sh
