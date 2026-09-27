# Build the dm-verity-capable workload kernel into the local mvm cache.
# Set MVM_KERNEL_SOURCE=download to use the hash-verified release artifact, or

# MVM_KERNEL_SOURCE=auto to prefer it and compile when no asset is available.
workload:
    cargo run -- kernel build --which workload

# Live macOS Apple-Silicon HVF proof for OCI --allow-host:
#  1. exact `machine run --image ... --allow-host ... -- ps aux` path

# 2. admit/deny relay proof over the host-vsock egress endpoint
hvf-oci-smoke:
    bash scripts/check-hvf-oci-allow-host-smoke.sh

# Live Apple-Silicon HVF warm-restore matrix. Requires the HVF warm capability

# to have passed its live continuity gate; it never enables that capability.
hvf-warm-restore:
    bash scripts/check-hvf-warm-restore.sh
