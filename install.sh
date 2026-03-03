#!/usr/bin/env bash
set -euo pipefail

# install.sh — download mvmctl and optionally bootstrap a dev/node/coordinator environment
#
# Usage:
#   # Binary-only install (default)
#   curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | bash
#
#   # Dev (macOS + Lima, or Linux dev)
#   curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | bash -s -- dev
#
#   # Node (staging/production Linux host)
#   curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | bash -s -- node \
#     --coordinator-url https://COORDINATOR:7777 --install-service
#
#   # Coordinator
#   curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | bash -s -- coordinator
#
# Flags:
#   dev|node|coordinator         Mode (optional first arg; omit for binary-only install)
#   --coordinator-url URL        Coordinator endpoint (node mode)
#   --interval-secs N            Agent reconcile interval (default: 15)
#   --install-service            Install and start systemd unit (node mode, Linux only)
#   --no-install-mvm             Skip downloading mvmctl (use existing mvmctl on PATH)
#   --mvm-path PATH              Use a specific mvmctl binary (skips download)
#
# Environment overrides:
#   MVM_VERSION=v0.1.0           GitHub Releases tag (omit or "latest" for latest)
#   MVM_INSTALL_DIR=/usr/local/bin
#   MVM_REPO=https://github.com/auser/mvm
#   MVM_COORDINATOR_URL=https://...
#   MVM_AGENT_INTERVAL_SECS=15
#   MVM_TLS_CA=/path/ca.pem
#   MVM_TLS_CERT=/path/node.crt
#   MVM_TLS_KEY=/path/node.key

# ---------------------------------------------------------------------------
# Constants and defaults
# ---------------------------------------------------------------------------

REPO="auser/mvm"
BINARY="mvmctl"
INSTALL_DIR="${MVM_INSTALL_DIR:-/usr/local/bin}"
MVM_VERSION="${MVM_VERSION:-}"

COORD_URL="${MVM_COORDINATOR_URL:-}"
INTERVAL="${MVM_AGENT_INTERVAL_SECS:-15}"

TLS_CA="${MVM_TLS_CA:-}"
TLS_CERT="${MVM_TLS_CERT:-}"
TLS_KEY="${MVM_TLS_KEY:-}"

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
    BOLD='\033[1m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    RESET='\033[0m'
else
    BOLD='' GREEN='' YELLOW='' RED='' RESET=''
fi

info()  { echo -e "${BOLD}${GREEN}==>${RESET} ${BOLD}$1${RESET}"; }
warn()  { echo -e "${BOLD}${YELLOW}warn:${RESET} $1" >&2; }
error() { echo -e "${RED}error:${RESET} $1" >&2; }
die()   { error "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

require() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat >&2 <<'EOF'
Usage:
  install.sh                                    Install mvmctl binary only
  install.sh dev [options]                      Install + dev bootstrap (macOS/Linux)
  install.sh node [options]                     Install + production node bootstrap (Linux)
  install.sh coordinator [options]              Install + coordinator bootstrap

Options:
  --coordinator-url URL    Coordinator endpoint (required for node agent service)
  --interval-secs N        Agent reconcile interval (default: 15)
  --install-service        Install and enable systemd unit (node mode, Linux only)
  --no-install-mvm         Skip binary download (use existing mvmctl on PATH)
  --mvm-path PATH          Use a specific mvmctl binary path (skips download)
  -h, --help               Show this help

Environment:
  MVM_VERSION              Pin release tag (e.g. v0.1.0); omit for latest
  MVM_INSTALL_DIR          Install directory (default: /usr/local/bin)
  MVM_REPO                 GitHub repo URL (default: https://github.com/auser/mvm)
  MVM_COORDINATOR_URL      Coordinator URL (same as --coordinator-url)
  MVM_AGENT_INTERVAL_SECS  Reconcile interval (same as --interval-secs)
  MVM_TLS_CA               Path to CA certificate
  MVM_TLS_CERT             Path to node certificate
  MVM_TLS_KEY              Path to node private key
EOF
    exit 2
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

MODE=""
NO_INSTALL_MVM="0"
MVM_PATH_OVERRIDE=""
INSTALL_SERVICE="0"

# First positional arg is mode (if it doesn't look like a flag)
if [[ $# -gt 0 ]] && [[ "$1" != -* ]]; then
    MODE="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --coordinator-url)   COORD_URL="${2:?--coordinator-url requires a value}"; shift 2 ;;
        --interval-secs)     INTERVAL="${2:?--interval-secs requires a value}"; shift 2 ;;
        --install-service)   INSTALL_SERVICE="1"; shift ;;
        --no-install-mvm)    NO_INSTALL_MVM="1"; shift ;;
        --mvm-path)          MVM_PATH_OVERRIDE="${2:?--mvm-path requires a value}"; shift 2 ;;
        -h|--help)           usage ;;
        *)                   die "Unknown argument: $1" ;;
    esac
done

# Validate mode if provided
if [[ -n "$MODE" ]]; then
    case "$MODE" in
        dev|node|coordinator) ;;
        *) die "Unknown mode: $MODE. Must be one of: dev, node, coordinator" ;;
    esac
fi

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Darwin) os="apple-darwin" ;;
        Linux)  os="unknown-linux-gnu" ;;
        *)      die "Unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64)         arch="x86_64" ;;
        aarch64|arm64)  arch="aarch64" ;;
        *)              die "Unsupported architecture: $arch" ;;
    esac

    echo "${arch}-${os}"
}

PLATFORM="$(detect_platform)"

case "$(uname -s)" in
    Darwin) OS_TYPE="darwin" ;;
    *)      OS_TYPE="linux" ;;
esac

# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

download() {
    local url="$1" dest="$2"
    if require curl; then
        curl -fsSL -o "$dest" "$url"
    elif require wget; then
        wget -qO "$dest" "$url"
    else
        die "curl or wget is required"
    fi
}

get_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    local response
    if require curl; then
        response="$(curl -fsSL "$url")"
    elif require wget; then
        response="$(wget -qO- "$url")"
    else
        die "curl or wget is required"
    fi
    echo "$response" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//'
}

# ---------------------------------------------------------------------------
# Binary installation
# ---------------------------------------------------------------------------

MVM_BIN=""

install_binary() {
    # --mvm-path override
    if [[ -n "$MVM_PATH_OVERRIDE" ]]; then
        if [[ ! -x "$MVM_PATH_OVERRIDE" ]]; then
            die "--mvm-path is not executable: $MVM_PATH_OVERRIDE"
        fi
        MVM_BIN="$MVM_PATH_OVERRIDE"
        return
    fi

    # --no-install-mvm
    if [[ "$NO_INSTALL_MVM" == "1" ]]; then
        if require mvmctl; then
            MVM_BIN="$(command -v mvmctl)"
            return
        fi
        die "--no-install-mvm set but mvmctl not found on PATH"
    fi

    # Resolve version
    local version
    if [[ -n "$MVM_VERSION" && "$MVM_VERSION" != "latest" ]]; then
        version="$MVM_VERSION"
        info "Using specified version: ${version}"
    else
        info "Fetching latest release..."
        version="$(get_latest_version)"
        if [[ -z "$version" ]]; then
            die "Could not determine latest version. Set MVM_VERSION=vX.Y.Z and retry."
        fi
        info "Latest version: ${version}"
    fi

    # Download archive
    local archive_name="${BINARY}-${PLATFORM}.tar.gz"
    local download_url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    info "Downloading ${download_url}..."
    download "$download_url" "${tmpdir}/${archive_name}" \
        || die "Download failed. Check that ${version} has a release for ${PLATFORM}."

    info "Extracting..."
    tar xzf "${tmpdir}/${archive_name}" -C "$tmpdir"

    # The archive contains mvmctl-<target>/mvmctl
    local extracted_dir="${tmpdir}/${BINARY}-${PLATFORM}"
    if [[ ! -f "${extracted_dir}/${BINARY}" ]]; then
        die "Binary not found in archive. Expected ${BINARY}-${PLATFORM}/${BINARY}"
    fi

    # Install binary
    info "Installing to ${INSTALL_DIR}/${BINARY}..."
    if [[ -w "$INSTALL_DIR" ]]; then
        mv "${extracted_dir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    else
        echo "  (requires sudo)"
        sudo mkdir -p "$INSTALL_DIR"
        sudo mv "${extracted_dir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    fi
    chmod +x "${INSTALL_DIR}/${BINARY}"

    # Install resources directory if present in archive
    if [[ -d "${extracted_dir}/resources" ]]; then
        info "Installing resources..."
        if [[ -w "$INSTALL_DIR" ]]; then
            rm -rf "${INSTALL_DIR}/resources"
            cp -r "${extracted_dir}/resources" "${INSTALL_DIR}/resources"
        else
            sudo rm -rf "${INSTALL_DIR}/resources"
            sudo cp -r "${extracted_dir}/resources" "${INSTALL_DIR}/resources"
        fi
    fi

    info "Installed ${BINARY} ${version} to ${INSTALL_DIR}/${BINARY}"
    MVM_BIN="${INSTALL_DIR}/${BINARY}"
}

# ---------------------------------------------------------------------------
# Prerequisite installation (only when a mode is specified)
# ---------------------------------------------------------------------------

install_prereqs_darwin() {
    if ! require brew; then
        info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        if [[ -x /opt/homebrew/bin/brew ]]; then eval "$(/opt/homebrew/bin/brew shellenv)"; fi
        if [[ -x /usr/local/bin/brew ]]; then eval "$(/usr/local/bin/brew shellenv)"; fi
    fi

    if [[ "$MODE" == "dev" ]]; then
        info "Ensuring Lima is installed..."
        brew install lima 2>/dev/null || brew upgrade lima 2>/dev/null || true
    fi
}

install_prereqs_linux() {
    if require apt-get; then
        sudo apt-get update -y
        sudo apt-get install -y curl ca-certificates tar jq coreutils util-linux || true
    elif require dnf; then
        sudo dnf install -y curl ca-certificates tar jq coreutils util-linux || true
    elif require yum; then
        sudo yum install -y curl ca-certificates tar jq coreutils util-linux || true
    else
        warn "No supported package manager found (apt/dnf/yum). Ensure curl/tar/jq are installed."
    fi
}

# ---------------------------------------------------------------------------
# Mode handlers
# ---------------------------------------------------------------------------

bootstrap_dev() {
    info "Running dev bootstrap..."
    "$MVM_BIN" bootstrap
    "$MVM_BIN" bootstrap --production || true

    echo ""
    info "Dev bootstrap complete."
    echo ""
    echo "  Next steps:"
    echo "    mvmctl dev       # launch the dev environment"
    echo ""
    if [[ -n "$COORD_URL" ]]; then
        echo "  Or start the agent:"
        echo "    $MVM_BIN agent serve --coordinator-url ${COORD_URL} --interval-secs ${INTERVAL}"
        echo ""
    fi
}

bootstrap_node() {
    if [[ "$OS_TYPE" != "linux" ]]; then
        die "Node mode requires Linux (Firecracker needs /dev/kvm)."
    fi
    if [[ ! -e /dev/kvm ]]; then
        die "/dev/kvm not found. Use a KVM-capable host (bare metal or nested virt enabled)."
    fi

    info "Running production bootstrap..."
    "$MVM_BIN" bootstrap --production

    if [[ "$INSTALL_SERVICE" != "1" ]]; then
        echo ""
        info "Node bootstrap complete."
        echo ""
        if [[ -n "$COORD_URL" ]]; then
            echo "  Start the agent (foreground):"
            echo "    $MVM_BIN agent serve --coordinator-url $COORD_URL --interval-secs ${INTERVAL}"
        else
            echo "  NOTE: --coordinator-url not provided."
            echo "  Start the agent later:"
            echo "    $MVM_BIN agent serve --coordinator-url https://COORDINATOR:7777 --interval-secs ${INTERVAL}"
        fi
        echo ""
        return
    fi

    # systemd service installation
    if ! require systemctl; then
        die "--install-service requested but systemctl not found (systemd required)."
    fi

    info "Installing systemd service: mvm-agent.service"

    local tls_args=""
    [[ -n "$TLS_CA"   ]] && tls_args="${tls_args} --tls-ca ${TLS_CA}"
    [[ -n "$TLS_CERT" ]] && tls_args="${tls_args} --tls-cert ${TLS_CERT}"
    [[ -n "$TLS_KEY"  ]] && tls_args="${tls_args} --tls-key ${TLS_KEY}"

    sudo tee /etc/systemd/system/mvm-agent.service >/dev/null <<UNIT
[Unit]
Description=mvm Node Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${MVM_BIN} agent serve --coordinator-url ${COORD_URL} --interval-secs ${INTERVAL}${tls_args}
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

    sudo systemctl daemon-reload
    sudo systemctl enable --now mvm-agent.service

    echo ""
    info "Service status:"
    sudo systemctl status mvm-agent.service --no-pager || true
    echo ""
    echo "  Verify:"
    echo "    $MVM_BIN node info --json"
    echo "    $MVM_BIN net verify"
    echo ""
}

bootstrap_coordinator() {
    info "Coordinator mode"
    if "$MVM_BIN" coordinator --help >/dev/null 2>&1; then
        "$MVM_BIN" coordinator bootstrap || true
    else
        warn "'mvmctl coordinator' subcommand not found. Start your coordinator service manually."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    info "Detected platform: ${PLATFORM}"

    # If a mode is specified, install prerequisites first
    if [[ -n "$MODE" ]]; then
        info "Mode: ${MODE}"
        if [[ "$OS_TYPE" == "darwin" ]]; then
            install_prereqs_darwin
        else
            install_prereqs_linux
        fi
    fi

    # Install the binary (or locate existing via --mvm-path / --no-install-mvm)
    install_binary

    # Verify
    info "Using mvmctl: ${MVM_BIN}"
    "${MVM_BIN}" --version 2>/dev/null || true

    # Binary-only install (no mode) — done
    if [[ -z "$MODE" ]]; then
        if [[ ":$PATH:" == *":${INSTALL_DIR}:"* ]]; then
            echo ""
            info "Run 'mvmctl bootstrap' to get started."
        else
            echo ""
            echo "  ${INSTALL_DIR} may not be in your PATH."
            echo "  Add it:  export PATH=\"${INSTALL_DIR}:\$PATH\""
        fi
        return
    fi

    # Run mode-specific bootstrap
    case "$MODE" in
        dev)          bootstrap_dev ;;
        node)         bootstrap_node ;;
        coordinator)  bootstrap_coordinator ;;
    esac
}

main
