#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# AirSnitch – Kali Linux Installer (Patched)
# ──────────────────────────────────────────────────────────────────────────────
# Installs AirSnitch + web control panel on Kali Linux (bare-metal / laptop).
#
#   - Clones and builds airsnitch from source (pinned commit)
#   - Installs all wireless dependencies
#   - Sets up a web UI on port 8080 for browser-based control
#   - Direct USB wireless adapter access (no Docker, no VMs)
#
# Original tool by Daniel Card (mr-r3b00t): https://github.com/mr-r3b00t/AirSnitcher
# Based on research by Mathy Vanhoef et al. (NDSS 2026): https://github.com/vanhoefm/airsnitch
#
# Patches applied vs original:
#   [1] Build failures no longer silently swallowed — logged to /tmp/airsnitch-build.log
#   [2] Monitor mode capability checked before install proceeds
#   [3] rfkill soft/hard block checked and resolved automatically
#   [4] NetworkManager unmanaged for test interfaces (session + persistent)
#   [5] Upstream airsnitch commit pinned + recorded at /opt/airsnitch/.install-commit
#   [6] Web UI hardened: localhost-only bind, systemd sandboxing
#   [7] Symlinks use explicit rm -f before ln -s to avoid stale file collisions
#   [8] stop.sh uses PID file instead of fragile pkill pattern
#
# Usage:  chmod +x install.sh && sudo ./install.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/airsnitch"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${AIRSNITCH_PORT:-8080}"
BUILD_LOG="/tmp/airsnitch-build.log"

AIRSNITCH_COMMIT="${AIRSNITCH_COMMIT:-}"
CONFIGURED_IFACES="${AIRSNITCH_IFACES:-}"

# ── Helpers ──────────────────────────────────────────────────────────────────

info()    { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "${RED}[-]${NC} $*"; exit 1; }

run_build() {
    local label="$1"; shift
    info "Running: ${label}..."
    if ! "$@" >> "${BUILD_LOG}" 2>&1; then
        warn "${label} reported errors — see ${BUILD_LOG} for details"
    fi
}

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "    _    _      ____        _ _       _     "
    echo "   / \  (_)_ __/ ___| _ __ (_) |_ ___| |__  "
    echo "  / _ \ | | '__\___ \| '_ \| | __/ __| '_ \ "
    echo " / ___ \| | |   ___) | | | | | || (__| | | |"
    echo "/_/   \_\_|_|  |____/|_| |_|_|\__\___|_| |_|"
    echo ""
    echo -e "${NC}${BOLD}  Wi-Fi Client Isolation Testing Toolkit${NC}"
    echo -e "  Kali Linux Installer (Patched)"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "This script must be run as root. Use: sudo ./install.sh"
    fi
}

# ── [FIX 3] rfkill check ─────────────────────────────────────────────────────

check_rfkill() {
    info "Checking rfkill state..."
    if rfkill list wifi 2>/dev/null | grep -q "Hard blocked: yes"; then
        fail "Wi-Fi is hardware-blocked (rfkill). Check your laptop's physical Wi-Fi switch, then re-run."
    fi
    if rfkill list wifi 2>/dev/null | grep -q "Soft blocked: yes"; then
        warn "Wi-Fi is software-blocked. Unblocking..."
        rfkill unblock wifi
        success "Wi-Fi software block cleared"
    else
        success "rfkill: Wi-Fi is not blocked"
    fi
}

# ── [FIX 2] Wireless adapter capability check ─────────────────────────────────

check_wireless() {
    info "Checking for monitor-mode-capable wireless adapters..."
    local found=0
    while IFS= read -r iface; do
        local phy
        phy=$(iw dev "$iface" info 2>/dev/null | awk '/wiphy/{print "phy"$2}') || continue
        if iw phy "$phy" info 2>/dev/null | grep -q "monitor"; then
            success "Monitor mode supported: ${iface}"
            found=1
        else
            warn "${iface} does not appear to support monitor mode"
        fi
    done < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')

    if [[ $found -eq 0 ]]; then
        warn "No injection-capable adapters detected."
        warn "Plug in your USB adapter before running attacks (alpha cards, RT3070/RT5572, AR9271, etc.)"
        warn "Continuing install — adapter can be inserted later."
    fi
}

# ── System dependencies ──────────────────────────────────────────────────────

install_deps() {
    info "Updating package lists..."
    apt-get update -qq

    info "Installing system dependencies..."
    apt-get install -y -qq \
        build-essential git python3 python3-pip python3-venv \
        libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
        libssl-dev libdbus-1-dev pkg-config \
        aircrack-ng dnsmasq tcpreplay macchanger iw \
        wireless-tools wpasupplicant net-tools iputils-ping \
        iproute2 tcpdump usbutils pciutils kmod rfkill \
        tmux curl wget \
        > /dev/null 2>&1

    success "System dependencies installed"
}

# ── [FIX 1, 5] Clone & build airsnitch ───────────────────────────────────────

install_airsnitch() {
    : > "${BUILD_LOG}"

    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        info "AirSnitch repo already exists at ${INSTALL_DIR}, pulling latest..."
        cd "${INSTALL_DIR}"
        git pull --quiet || warn "git pull failed — using existing checkout"
    else
        info "Cloning AirSnitch from vanhoefm/airsnitch..."
        rm -rf "${INSTALL_DIR}"
        git clone https://github.com/vanhoefm/airsnitch.git "${INSTALL_DIR}"
    fi

    cd "${INSTALL_DIR}"

    if [[ -n "${AIRSNITCH_COMMIT}" ]]; then
        info "Checking out pinned commit: ${AIRSNITCH_COMMIT}"
        git checkout "${AIRSNITCH_COMMIT}" || fail "Could not checkout commit ${AIRSNITCH_COMMIT}"
    fi

    local actual_commit
    actual_commit=$(git rev-parse HEAD)
    echo "${actual_commit}" > "${INSTALL_DIR}/.install-commit"
    info "Pinned to commit: ${actual_commit}"

    git submodule update --init --recursive

    [[ -f setup.sh ]] && chmod +x setup.sh && run_build "setup.sh" bash setup.sh

    cd "${INSTALL_DIR}/airsnitch/research" 2>/dev/null || {
        warn "research/ subdirectory not found — repo layout may have changed upstream"
        return
    }

    if [[ -f build.sh ]]; then
        chmod +x build.sh
        run_build "build.sh (modified wpa_supplicant)" bash build.sh
    fi

    if [[ -f pysetup.sh ]]; then
        chmod +x pysetup.sh
        run_build "pysetup.sh" bash pysetup.sh
    fi

    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        . venv/bin/activate
        pip install --upgrade pip --quiet
        [[ -f requirements.txt ]] && pip install -r requirements.txt --quiet
        # pycryptodomex must be installed alongside pycryptodome so that
        # 'from Crypto.Cipher import AES' resolves correctly inside the venv.
        # Without this, airsnitch.py throws ModuleNotFoundError: No module named 'Crypto'
        pip install pycryptodomex --quiet
        deactivate
    fi

    success "AirSnitch built at ${INSTALL_DIR}/airsnitch/research/"
    info "Build log: ${BUILD_LOG}"
}

# ── [FIX 4] NetworkManager suppression ───────────────────────────────────────

configure_networkmanager() {
    info "Configuring NetworkManager to release wireless test interfaces..."
    local nm_airsnitch_conf="/etc/NetworkManager/conf.d/airsnitch-unmanaged.conf"

    if ! command -v nmcli &>/dev/null && ! systemctl is-active --quiet NetworkManager 2>/dev/null; then
        info "NetworkManager not detected — skipping NM configuration"
        return
    fi

    {
        echo "# Generated by AirSnitcher installer"
        echo "# Prevents NetworkManager from reasserting control of wireless test interfaces."
        echo "[keyfile]"
        if [[ -n "${CONFIGURED_IFACES}" ]]; then
            local nm_unmanaged
            nm_unmanaged=$(echo "${CONFIGURED_IFACES}" | tr ' ' '\n' \
                | awk '{printf "interface-name:%s;", $1}' | sed 's/;$//')
            echo "unmanaged-devices=${nm_unmanaged}"
        fi
    } > "${nm_airsnitch_conf}"

    systemctl reload NetworkManager 2>/dev/null || true
    success "NetworkManager drop-in config written to ${nm_airsnitch_conf}"
}

# ── Install web control panel ────────────────────────────────────────────────

install_web() {
    info "Installing web control panel..."

    mkdir -p "${INSTALL_DIR}/web/templates" "${INSTALL_DIR}/web/static/css" "${INSTALL_DIR}/web/static/js"
    cp "${SCRIPT_DIR}/web/server.py"                "${INSTALL_DIR}/web/"
    cp "${SCRIPT_DIR}/web/requirements.txt"         "${INSTALL_DIR}/web/"
    cp "${SCRIPT_DIR}/web/templates/index.html"     "${INSTALL_DIR}/web/templates/"
    cp "${SCRIPT_DIR}/web/static/css/style.css"     "${INSTALL_DIR}/web/static/css/"
    cp "${SCRIPT_DIR}/web/static/js/app.js"         "${INSTALL_DIR}/web/static/js/"

    mkdir -p "${INSTALL_DIR}/configs"
    if [[ -f "${SCRIPT_DIR}/config/client.conf.example" ]]; then
        cp "${SCRIPT_DIR}/config/client.conf.example" "${INSTALL_DIR}/configs/"
    fi
    if [[ ! -f "${INSTALL_DIR}/configs/client.conf" ]]; then
        cp "${INSTALL_DIR}/configs/client.conf.example" "${INSTALL_DIR}/configs/client.conf" 2>/dev/null || true
    fi

    if [[ ! -d "${INSTALL_DIR}/web/.venv" ]]; then
        python3 -m venv "${INSTALL_DIR}/web/.venv"
    fi
    "${INSTALL_DIR}/web/.venv/bin/pip" install --quiet --upgrade pip
    "${INSTALL_DIR}/web/.venv/bin/pip" install --quiet -r "${INSTALL_DIR}/web/requirements.txt"

    success "Web control panel installed"
}

# ── [FIX 6, 7, 8] Service + launchers ────────────────────────────────────────

install_service() {
    info "Creating launcher scripts..."

    cat > "${INSTALL_DIR}/start.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
PORT="${AIRSNITCH_PORT:-8080}"
HOST="${AIRSNITCH_HOST:-127.0.0.1}"
PID_FILE="/run/airsnitch-web.pid"

# ── Auto monitor mode setup ───────────────────────────────────────────────────
# Checks for an existing monitor interface; if none found, runs airmon-ng
# automatically on the first suitable adapter. Works on both x86 and ARM64.
setup_monitor_mode() {
    # Already have a monitor interface? (|| true prevents pipefail on no-match)
    local mon_iface
    mon_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -E 'mon$' | head -1 || true)
    if [[ -n "${mon_iface}" ]]; then
        echo "[+] Monitor interface already active: ${mon_iface}"
        export AIRSNITCH_MON_IFACE="${mon_iface}"
        return 0
    fi

    # Find first non-monitor wireless interface
    local base_iface
    base_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -vE 'mon$' | head -1 || true)
    if [[ -z "${base_iface}" ]]; then
        echo "[!] No wireless interfaces found — plug in your adapter and retry."
        return 0
    fi

    echo "[*] No monitor interface detected. Setting up monitor mode on ${base_iface}..."
    airmon-ng check kill > /dev/null 2>&1 || true
    airmon-ng start "${base_iface}" > /dev/null 2>&1 || true

    mon_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -E 'mon$' | head -1 || true)
    if [[ -n "${mon_iface}" ]]; then
        echo "[+] Monitor interface created: ${mon_iface}"
        export AIRSNITCH_MON_IFACE="${mon_iface}"
    else
        echo "[!] airmon-ng did not create a monitor interface."
        echo "[!] Try manually: airmon-ng check kill && airmon-ng start ${base_iface}"
        export AIRSNITCH_MON_IFACE="${base_iface}"
    fi
}

setup_monitor_mode

if [[ -n "${AIRSNITCH_IFACES:-}" ]]; then
    for iface in ${AIRSNITCH_IFACES}; do
        nmcli device set "$iface" managed no 2>/dev/null && \
            echo "[+] NetworkManager released: ${iface}" || true
    done
    trap 're_enable_ifaces' EXIT
fi

re_enable_ifaces() {
    if [[ -n "${AIRSNITCH_IFACES:-}" ]]; then
        for iface in ${AIRSNITCH_IFACES}; do
            nmcli device set "$iface" managed yes 2>/dev/null || true
            echo "[*] NetworkManager re-enabled: ${iface}"
        done
    fi
    rm -f "${PID_FILE}"
}

echo ""
echo "  AirSnitch Control Panel"
echo "  http://${HOST}:${PORT}"
[[ -n "${AIRSNITCH_MON_IFACE:-}" ]] && \
    echo "  Monitor interface: ${AIRSNITCH_MON_IFACE}"
echo "  Press Ctrl+C to stop."
echo ""

echo $$ > "${PID_FILE}"
exec /opt/airsnitch/web/.venv/bin/python3 /opt/airsnitch/web/server.py \
    --host "${HOST}" --port "${PORT}"
EOF
    chmod +x "${INSTALL_DIR}/start.sh"

    cat > "${INSTALL_DIR}/stop.sh" << 'EOF'
#!/usr/bin/env bash
PID_FILE="/run/airsnitch-web.pid"
if [[ -f "${PID_FILE}" ]]; then
    PID=$(cat "${PID_FILE}")
    if kill "${PID}" 2>/dev/null; then
        rm -f "${PID_FILE}"
        echo "[+] AirSnitch web UI stopped (PID ${PID})."
    else
        echo "[!] Process ${PID} not found — may have already exited."
        rm -f "${PID_FILE}"
    fi
else
    echo "[!] No PID file found at ${PID_FILE} — is AirSnitch running?"
fi
EOF
    chmod +x "${INSTALL_DIR}/stop.sh"

    rm -f /usr/local/bin/airsnitch-web /usr/local/bin/airsnitch-stop
    ln -s "${INSTALL_DIR}/start.sh" /usr/local/bin/airsnitch-web
    ln -s "${INSTALL_DIR}/stop.sh"  /usr/local/bin/airsnitch-stop

    {
        echo "[Unit]"
        echo "Description=AirSnitch Web Control Panel"
        echo "After=network.target"
        echo ""
        echo "[Service]"
        echo "Type=simple"
        echo "Environment=AIRSNITCH_PORT=${PORT}"
        echo "Environment=AIRSNITCH_HOST=127.0.0.1"
        [[ -n "${CONFIGURED_IFACES}" ]] && echo "Environment=AIRSNITCH_IFACES=${CONFIGURED_IFACES}"
        echo "ExecStart=/opt/airsnitch/web/.venv/bin/python3 /opt/airsnitch/web/server.py"
        echo "WorkingDirectory=/opt/airsnitch"
        echo "Restart=on-failure"
        echo "NoNewPrivileges=yes"
        echo "PrivateTmp=yes"
        echo "ProtectSystem=strict"
        echo "ReadWritePaths=/opt/airsnitch /run"
        echo ""
        echo "[Install]"
        echo "WantedBy=multi-user.target"
    } > /etc/systemd/system/airsnitch-web.service
    systemctl daemon-reload
    success "Launcher scripts created"
}

# ── Setup wizard ─────────────────────────────────────────────────────────────

prompt_config() {
    echo -e "${CYAN}${BOLD}━━━ Setup Wizard ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # 1. Web UI port
    read -r -p "$(echo -e "  Web UI port ${BLUE}[${PORT}]${NC}: ")" _input
    if [[ -n "${_input}" ]]; then
        if [[ "${_input}" =~ ^[0-9]+$ ]] && (( _input >= 1 && _input <= 65535 )); then
            PORT="${_input}"
        else
            warn "Invalid port '${_input}' — keeping default ${PORT}"
        fi
    fi

    # 2. Commit pin
    echo ""
    read -r -p "$(echo -e "  Pin to a specific upstream commit? ${BLUE}[leave blank for latest]${NC}: ")" _input
    AIRSNITCH_COMMIT="${_input:-}"

    # 3. Wireless interfaces to release from NetworkManager
    echo ""
    local detected=()
    while IFS= read -r iface; do
        detected+=("${iface}")
    done < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')

    if [[ ${#detected[@]} -gt 0 ]]; then
        echo -e "  Detected wireless interfaces: ${CYAN}${detected[*]}${NC}"
    else
        echo -e "  ${YELLOW}No wireless interfaces detected yet — you can still enter names manually.${NC}"
    fi
    read -r -p "$(echo -e "  Interfaces to release from NetworkManager ${BLUE}[e.g. wlan1 wlan2, blank to skip]${NC}: ")" _input
    CONFIGURED_IFACES="${_input:-}"

    # 4. Summary + confirm
    echo ""
    echo -e "${CYAN}${BOLD}━━━ Install Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  Install directory : ${CYAN}${INSTALL_DIR}${NC}"
    echo -e "  Web UI port       : ${CYAN}${PORT}${NC}"
    echo -e "  Commit pin        : ${CYAN}${AIRSNITCH_COMMIT:-latest}${NC}"
    echo -e "  NM-release ifaces : ${CYAN}${CONFIGURED_IFACES:-none}${NC}"
    echo -e "  Build log         : ${CYAN}${BUILD_LOG}${NC}"
    echo ""
    read -r -p "$(echo -e "  Proceed with installation? ${BOLD}[y/N]${NC}: ")" _confirm
    case "${_confirm}" in
        [yY]|[yY][eE][sS]) echo "" ;;
        *) echo "Aborted."; exit 0 ;;
    esac
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    banner
    check_root
    prompt_config
    install_deps
    check_rfkill
    check_wireless
    configure_networkmanager
    install_airsnitch
    install_web
    install_service

    local install_commit="(unknown)"
    [[ -f "${INSTALL_DIR}/.install-commit" ]] && \
        install_commit=$(cat "${INSTALL_DIR}/.install-commit")

    echo ""
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  AirSnitch installation complete!${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Upstream commit pinned:${NC} ${CYAN}${install_commit}${NC}"
    echo -e "  ${BOLD}Build log:${NC}             ${CYAN}${BUILD_LOG}${NC}"
    echo ""
    echo -e "  ${BOLD}Start the web UI:${NC}"
    echo -e "    ${CYAN}sudo airsnitch-web${NC}"
    echo -e "    Then open ${CYAN}http://localhost:${PORT}${NC}"
    echo ""
    echo -e "  ${BOLD}With NetworkManager interface release:${NC}"
    echo -e "    ${CYAN}sudo AIRSNITCH_IFACES=\"wlan1 wlan2\" airsnitch-web${NC}"
    echo ""
    echo -e "  ${BOLD}Run directly (recommended — avoids sudo venv issues):${NC}"
    echo -e "    ${CYAN}cd /opt/airsnitch/airsnitch/research${NC}"
    echo -e "    ${CYAN}source venv/bin/activate${NC}"
    echo -e "    ${CYAN}venv/bin/python3 ./airsnitch.py <iface> --check-gtk-shared client.conf${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}━━━ Important operational notes ━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # ARM64 warning
    local arch
    arch=$(uname -m)
    if [[ "${arch}" == "aarch64" || "${arch}" == "arm64" ]]; then
        echo -e "  ${YELLOW}[ARM64 DETECTED]${NC} The web UI 'Monitor Mode' button may not work"
        echo -e "  reliably on ARM64. Set monitor mode manually before starting the UI:"
        echo -e "    ${CYAN}airmon-ng check kill${NC}"
        echo -e "    ${CYAN}airmon-ng start <iface>${NC}   # creates <iface>mon e.g. wlan0mon"
        echo -e "  Then use ${CYAN}wlan0mon${NC} (or equivalent) as your interface in the UI/CLI."
        echo ""
    fi

    echo -e "  ${BOLD}Do NOT use 'sudo ./airsnitch.py':${NC}"
    echo -e "  sudo drops the venv, causing 'No module named Crypto'."
    echo -e "  Always run via the venv python directly:"
    echo -e "    ${CYAN}venv/bin/python3 ./airsnitch.py ...${NC}"
    echo ""
    echo -e "  ${BOLD}client.conf must be edited before running:${NC}"
    echo -e "    ${CYAN}nano /opt/airsnitch/airsnitch/research/client.conf${NC}"
    echo -e "  Set ${BOLD}ssid${NC}, ${BOLD}psk${NC}, and ${BOLD}scan_freq${NC} in BOTH network blocks."
    echo -e "  Channel → frequency reference:"
    echo -e "    Ch 1=2412  Ch 6=2437  Ch 9=2452  Ch 11=2462"
    echo -e "    Ch 36=5180 Ch 40=5200 Ch 44=5220 Ch 48=5240"
    echo -e "  (Run ${CYAN}airodump-ng <iface>mon${NC} to find your target's channel)"
    echo ""
    echo -e "  ${BOLD}Web UI Terminal tab:${NC} click Connect → open a root shell"
    echo -e "  in the browser, then run airsnitch commands directly from there."
    echo ""
}

main "$@"
