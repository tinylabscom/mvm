set working-directory := "../.."

# Create a disposable Intel GCP Spot host, run the pinned CVE-2026-80521
# containment witness, download its evidence, and delete the host.
cve-3655-gcp *ARGS:
    ./scripts/run-cve-2026-80521-gcp.sh {{ARGS}}
