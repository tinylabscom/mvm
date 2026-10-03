set working-directory := "../.."

# Creates a disposable Intel GCP Spot host, runs the command with nested KVM,
# downloads its results, and deletes the host.

# Run one repository test command on a disposable GCP nested-KVM host
gcp-kvm PROGRAM *ARGS:
    ./scripts/run-gcp-kvm-test.sh -- {{PROGRAM}} {{ARGS}}

# Creates a disposable Intel GCP Spot host, runs the witness, downloads its
# evidence, and deletes the host.

# Run the pinned CVE-2026-80521 containment witness on a disposable GCP host
cve-3655-gcp *ARGS:
    ./scripts/run-cve-2026-80521-gcp.sh {{ARGS}}
