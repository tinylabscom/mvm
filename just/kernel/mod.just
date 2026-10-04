set working-directory := "../.."

# Set MVM_KERNEL_SOURCE=download to use the hash-verified release artifact, or
# MVM_KERNEL_SOURCE=auto to prefer it and compile when no asset is available.

# Build the dm-verity-capable workload kernel into the local mvm cache
workload:
    cargo run -- kernel build --which workload

# Proves the NIC-less guest runtime and production FlowMux HTTPS admit/deny
# behavior for OCI --allow-host.

# Live Apple-Silicon HVF smoke of OCI --allow-host egress
hvf-oci-smoke:
    bash scripts/check-hvf-oci-allow-host-smoke.sh

# Requires the HVF warm capability to have passed its live continuity gate; it
# never enables that capability.

# Live Apple-Silicon HVF warm-restore matrix
hvf-warm-restore:
    bash scripts/check-hvf-warm-restore.sh
