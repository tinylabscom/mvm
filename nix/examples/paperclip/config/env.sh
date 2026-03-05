# Optional environment variables for Paperclip server
# Mount this directory with: -v ./config:/mnt/config
# Sourced at runtime from /mnt/config/env.sh

# Server port (default: 3100)
# export PORT=3100

# Deployment mode: local_trusted (no auth) or authenticated
# export PAPERCLIP_DEPLOYMENT_MODE=local_trusted

# Deployment exposure: private (LAN/VPN) or public (internet-facing)
# export PAPERCLIP_DEPLOYMENT_EXPOSURE=private

# Instance identifier (default: "default")
# export PAPERCLIP_INSTANCE_ID=default

# Node.js memory limit (default: V8 auto-sizes based on available RAM)
# export NODE_OPTIONS="--max-old-space-size=2048"
