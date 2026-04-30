#!/usr/bin/env bash
# Install mvm-agent systemd unit file and create required directories.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_FILE="${SCRIPT_DIR}/../deploy/systemd/mvm-agent.service"

if [ ! -f "$UNIT_FILE" ]; then
    echo "ERROR: Unit file not found at $UNIT_FILE"
    exit 1
fi

echo "Installing mvm-agent systemd unit..."

# Create required directories
sudo mkdir -p /var/lib/mvm/tenants
sudo mkdir -p /var/lib/mvm/keys
sudo mkdir -p /etc/mvm/certs
sudo mkdir -p /sys/fs/cgroup/mvm

# Set directory permissions
sudo chmod 0700 /var/lib/mvm/keys
sudo chmod 0755 /var/lib/mvm
sudo chmod 0700 /etc/mvm/certs

# Install unit file
sudo cp "$UNIT_FILE" /etc/systemd/system/mvm-agent.service
sudo systemctl daemon-reload

echo "Installed. Configure /etc/mvm/desired.json and certs, then:"
echo "  sudo systemctl enable --now mvm-agent"
