#!/usr/bin/env bash
#
# OpenClaw Setup Kit - VPS entrypoint
# Run from SSH on your Linux server:
#   bash Setup-VPS.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$SCRIPT_DIR/Setup.command"
