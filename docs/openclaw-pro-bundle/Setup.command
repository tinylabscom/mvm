#!/usr/bin/env bash
#
# OpenClaw Setup Kit - One-click setup for macOS and Linux/VPS.
# Double-click on macOS, or run "bash Setup.command" on Linux/VPS.
#

set -euo pipefail

if [ -t 1 ]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    NC=$'\033[0m'
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    BOLD=""
    DIM=""
    NC=""
fi

cd "$(dirname "$0")" 2>/dev/null || true
clear 2>/dev/null || true

PLATFORM=""
WORKSPACE="$HOME/.openclaw/workspace"
CONFIG_FILE="$HOME/.openclaw/openclaw.json"

header() {
    echo ""
    echo -e "${BOLD}-------------------------------------------------------${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}-------------------------------------------------------${NC}"
    echo ""
}

success() { echo -e "  ${GREEN}[OK]${NC} $1"; }
info()    { echo -e "  ${DIM}$1${NC}"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "  ${RED}[X]${NC} $1"; }

sanitize_line() {
    printf '%s' "$1" | tr '\r\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

append_path_candidate() {
    local path_candidate="$1"
    [ -d "$path_candidate" ] || return 0
    case ":$PATH:" in
        *":$path_candidate:"*) ;;
        *) PATH="$path_candidate:$PATH" ;;
    esac
}

refresh_path() {
    append_path_candidate "$HOME/.openclaw/bin"
    append_path_candidate "$HOME/.npm-global/bin"
    append_path_candidate "$HOME/.local/bin"
    append_path_candidate "/opt/homebrew/bin"
    append_path_candidate "/usr/local/bin"

    if command -v npm >/dev/null 2>&1; then
        local npm_prefix
        npm_prefix="$(npm prefix -g 2>/dev/null || true)"
        if [ -n "$npm_prefix" ]; then
            append_path_candidate "$npm_prefix"
            append_path_candidate "$npm_prefix/bin"
        fi
    fi
    export PATH
}

detect_platform() {
    case "$(uname -s)" in
        Darwin) PLATFORM="macos" ;;
        Linux) PLATFORM="linux" ;;
        *)
            fail "This setup supports macOS and Linux only."
            echo "  Windows users: https://docs.openclaw.ai"
            exit 1
            ;;
    esac
}

is_headless_session() {
    if [ -n "${SSH_CONNECTION:-}" ] || [ -n "${SSH_CLIENT:-}" ] || [ -n "${SSH_TTY:-}" ]; then
        return 0
    fi
    if [ "$PLATFORM" = "linux" ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
        return 0
    fi
    return 1
}

open_url_if_possible() {
    local url="$1"
    if [ "$PLATFORM" = "macos" ]; then
        open "$url" >/dev/null 2>&1 || true
        return 0
    fi
    if [ "$PLATFORM" = "linux" ] && ! is_headless_session && command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$url" >/dev/null 2>&1 || true
    fi
}

install_openclaw_if_missing() {
    refresh_path

    if command -v openclaw >/dev/null 2>&1; then
        success "OpenClaw already installed"
        return 0
    fi

    header "Installing OpenClaw"
    echo "  Using the official installer from ${BLUE}https://openclaw.ai${NC}"
    echo "  This also installs Node.js 22+ if needed."
    echo ""

    local installer_tmp
    installer_tmp="$(mktemp "${TMPDIR:-/tmp}/openclaw-installer.XXXXXX")"

    if ! curl -fsSL --proto '=https' --tlsv1.2 https://openclaw.ai/install.sh -o "$installer_tmp"; then
        rm -f "$installer_tmp"
        fail "Could not download the OpenClaw installer."
        echo "  Check internet access and try again."
        exit 1
    fi

    chmod +x "$installer_tmp"
    if ! bash "$installer_tmp" --no-onboard; then
        rm -f "$installer_tmp"
        fail "OpenClaw installation failed."
        echo "  Re-run this script. If it keeps failing: https://docs.openclaw.ai/install"
        exit 1
    fi
    rm -f "$installer_tmp"

    refresh_path
    if ! command -v openclaw >/dev/null 2>&1; then
        fail "OpenClaw installed, but this shell cannot find it yet."
        echo "  Close this window, open a new terminal, and run Setup.command again."
        exit 1
    fi

    success "OpenClaw installed"
}

prompt_required() {
    local prompt="$1"
    local value=""
    while true; do
        read -r -p "  $prompt" value
        value="$(sanitize_line "$value")"
        if [ -n "$value" ]; then
            printf '%s' "$value"
            return 0
        fi
        fail "Please enter a value."
    done
}

prompt_api_key() {
    local key=""
    while true; do
        echo ""
        read -r -s -p "  Paste your Anthropic API key: " key
        echo ""
        key="$(sanitize_line "$key")"
        if [ -z "$key" ]; then
            fail "No key entered."
            continue
        fi

        if [[ "$key" != sk-ant-* ]]; then
            warn "This key does not start with sk-ant-."
            read -r -p "  Continue anyway? (y/N): " continue_anyway
            continue_anyway="$(sanitize_line "${continue_anyway:-}")"
            case "$continue_anyway" in
                y|Y|yes|YES) ;;
                *) continue ;;
            esac
        fi

        printf '%s' "$key"
        return 0
    done
}

run_onboard() {
    local api_key="$1"

    header "Connecting OpenClaw To Claude"
    echo "  Applying safe defaults automatically."
    echo "  You do not need to choose advanced options."
    echo ""

    if ANTHROPIC_API_KEY="$api_key" openclaw onboard \
        --non-interactive \
        --mode local \
        --auth-choice apiKey \
        --anthropic-api-key "$api_key" \
        --gateway-port 18789 \
        --gateway-bind loopback \
        --install-daemon \
        --daemon-runtime node \
        --skip-skills \
        >/dev/null 2>&1; then
        success "OpenClaw configured"
        return 0
    fi

    warn "Automatic setup failed. Running guided quickstart."
    echo ""
    ANTHROPIC_API_KEY="$api_key" openclaw onboard --flow quickstart --install-daemon --anthropic-api-key "$api_key"
    success "OpenClaw configured"
}

write_identity_files() {
    local user_name="$1"
    local agent_name="$2"
    local communication_style="$3"
    local user_work="$4"
    local primary_use="$5"

    mkdir -p "$WORKSPACE"

    {
        printf '# %s\n\n' "$agent_name"
        printf 'You are %s, a personal AI assistant for %s.\n\n' "$agent_name" "$user_name"
        printf '## Communication Style\n%s\n\n' "$communication_style"
        printf '## Values\n'
        printf '%s\n' '- Proactive: anticipate needs and suggest next steps.'
        printf '%s\n' '- Honest: call out weak assumptions and hidden risks.'
        printf '%s\n' '- Efficient: prefer practical execution over theory.'
        printf '%s\n\n' '- Adaptive: learn from feedback and improve over time.'
        printf '## Boundaries\n'
        printf '%s\n' '- Confirm before spending money.'
        printf '%s\n' '- Confirm before contacting new people.'
        printf '%s\n\n' '- If uncertain, ask for clarification instead of guessing.'
        printf '## Context\n'
        printf '%s work: %s\n' "$user_name" "$user_work"
        printf 'Primary focus: %s\n' "$primary_use"
    } > "$WORKSPACE/SOUL.md"

    {
        printf '# About %s\n\n' "$user_name"
        printf '## Work\n%s\n\n' "$user_work"
        printf '## Main Use Cases For %s\n%s\n\n' "$agent_name" "$primary_use"
        printf '## Projects\n'
        printf '(Keep this updated so your assistant has current context.)\n\n'
        printf '## Preferences\n'
        printf '(Add communication and workflow preferences over time.)\n'
    } > "$WORKSPACE/USER.md"

    {
        printf '# %s Memory\n\n' "$agent_name"
        printf 'Use this file for long-term memory and corrections.\n\n'
        printf '## Facts Learned\n\n'
        printf '## Decisions Made\n\n'
        printf '## Preferences Discovered\n'
    } > "$WORKSPACE/MEMORY.md"

    success "Identity files written to $WORKSPACE"
}

restart_gateway() {
    info "Starting OpenClaw gateway..."
    openclaw gateway restart >/dev/null 2>&1 || openclaw gateway start >/dev/null 2>&1 || true
    sleep 3

    if openclaw gateway status >/dev/null 2>&1; then
        success "Gateway is running"
    else
        warn "Gateway may still be booting."
        echo "  If dashboard does not load, run: openclaw gateway start"
    fi
}

show_dashboard_access() {
    local agent_name="$1"
    local dashboard_url="http://127.0.0.1:18789"

    if is_headless_session; then
        local remote_user
        local remote_host
        remote_user="$(id -un)"
        remote_host="$(printf '%s' "${SSH_CONNECTION:-}" | awk '{print $3}')"
        [ -n "$remote_host" ] || remote_host="<your-server-ip>"

        header "$agent_name Is Ready"
        echo "  This looks like a VPS/SSH session (no local browser detected)."
        echo "  Keeping gateway on localhost for safety."
        echo ""
        echo "  On your local computer, run:"
        printf "    ssh -L 18789:127.0.0.1:18789 %s@%s\n" "$remote_user" "$remote_host"
        echo ""
        echo "  Then open this in your local browser:"
        printf "    %s\n" "$dashboard_url"
        return 0
    fi

    header "$agent_name Is Ready"
    echo "  Opening your dashboard now..."
    echo ""

    openclaw dashboard >/dev/null 2>&1 &
}

header "OpenClaw Setup Kit"
echo "  This script sets up OpenClaw for complete beginners."
echo "  It works on macOS and Linux/VPS."
echo "  Your API key stays on your machine and is never sent to SkillStack."
echo ""

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    warn "Running as root is not recommended. Use a normal user account if possible."
fi

detect_platform
success "Detected platform: $PLATFORM"

install_openclaw_if_missing

NEED_ONBOARD=true
API_KEY=""

if [ -f "$CONFIG_FILE" ]; then
    success "Found existing OpenClaw config ($CONFIG_FILE)"
    echo ""
    echo "  1) Keep existing provider key and settings (recommended)"
    echo "  2) Reconfigure with a new API key"
    echo ""
    read -r -p "  Pick 1-2 [1]: " config_choice
    config_choice="$(sanitize_line "${config_choice:-}")"
    case "$config_choice" in
        2) NEED_ONBOARD=true ;;
        *) NEED_ONBOARD=false ;;
    esac
fi

if [ "$NEED_ONBOARD" = true ]; then
    header "Step 1 of 3: API Key"
    echo "  Get your key at ${BLUE}https://console.anthropic.com/settings/keys${NC}"
    echo "  It starts with ${BOLD}sk-ant-${NC}"
    echo ""
    open_url_if_possible "https://console.anthropic.com/settings/keys"
    API_KEY="$(prompt_api_key)"
    success "API key captured (hidden)"
else
    info "Skipping provider setup. Keeping existing OpenClaw config."
fi

header "Step 2 of 3: Personalize Your Assistant"
echo "  This builds your SOUL.md, USER.md, and MEMORY.md files."
echo ""

USER_NAME="$(prompt_required "Your first name: ")"
AGENT_NAME="$(prompt_required "Assistant name (example: Atlas): ")"
echo ""

echo -e "  ${BOLD}How should $AGENT_NAME talk to you?${NC}"
echo "    1) Casual"
echo "    2) Direct"
echo "    3) Technical"
echo "    4) Warm"
read -r -p "  Pick 1-4 [2]: " style_choice
style_choice="$(sanitize_line "${style_choice:-}")"
case "$style_choice" in
    1) COMM_STYLE="Casual and conversational. Friendly, clear, and practical." ;;
    3) COMM_STYLE="Technical and precise. Detailed, exact, and explicit about tradeoffs." ;;
    4) COMM_STYLE="Warm and patient. Encouraging, clear, and easy to follow." ;;
    *) COMM_STYLE="Direct and concise. No fluff, clear actions, fast answers." ;;
esac

echo ""
read -r -p "  What do you do for work? (one sentence): " USER_WORK_RAW
USER_WORK="$(sanitize_line "${USER_WORK_RAW:-}")"
[ -n "$USER_WORK" ] || USER_WORK="Not shared yet."

echo ""
echo -e "  ${BOLD}Primary use case for $AGENT_NAME:${NC}"
echo "    1) Writing"
echo "    2) Research"
echo "    3) Coding"
echo "    4) Business ops"
echo "    5) Everything"
read -r -p "  Pick 1-5 [5]: " use_choice
use_choice="$(sanitize_line "${use_choice:-}")"
case "$use_choice" in
    1) PRIMARY_USE="Writing and content creation" ;;
    2) PRIMARY_USE="Research and analysis" ;;
    3) PRIMARY_USE="Coding and automation" ;;
    4) PRIMARY_USE="Business operations and planning" ;;
    *) PRIMARY_USE="General day-to-day assistance" ;;
esac

header "Step 3 of 3: Final Setup"
if [ "$NEED_ONBOARD" = true ]; then
    run_onboard "$API_KEY"
    API_KEY=""
fi

write_identity_files "$USER_NAME" "$AGENT_NAME" "$COMM_STYLE" "$USER_WORK" "$PRIMARY_USE"
restart_gateway
show_dashboard_access "$AGENT_NAME"

echo ""
echo "  Next: Check the Day 1 folder for first prompts and cost basics."
echo "  Re-run this script any time to update your assistant identity."
echo ""

if [ -t 0 ]; then
    read -r -p "  Press Enter to close..." _
fi
