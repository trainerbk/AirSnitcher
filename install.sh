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
#   [9] wpa_supplicant symlink auto-fixed after build (wrong relative path)
#   [10] pycryptodomex installed to fix 'No module named Crypto' in venv
#   [11] airsnitch-run wrapper handles monitor mode + venv + correct args automatically
#   [12] Interactive client.conf setup during install
#
# Usage:  chmod +x install.sh && sudo ./install.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
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

    # [FIX 9] build.sh places wpa_supplicant at airsnitch/wpa_supplicant/ but
    # airsnitch.py resolves it relative to research/ as ../wpa_supplicant/.
    # Symlinking the whole directory under research/ fixes the path without
    # touching the build output.
    local wpa_bin
    wpa_bin=$(find "${INSTALL_DIR}" -name "wpa_supplicant" -type f 2>/dev/null | head -1 || true)
    if [[ -n "${wpa_bin}" ]]; then
        local wpa_dir
        wpa_dir=$(dirname "${wpa_bin}")
        rm -rf "${INSTALL_DIR}/airsnitch/research/wpa_supplicant"
        ln -sf "${wpa_dir}" "${INSTALL_DIR}/airsnitch/research/wpa_supplicant"
        success "wpa_supplicant symlinked → research/wpa_supplicant"
    else
        warn "wpa_supplicant binary not found after build — check ${BUILD_LOG}"
    fi

    success "AirSnitch built at ${INSTALL_DIR}/airsnitch/research/"
    info "Build log: ${BUILD_LOG}"
}

# ── [FIX 12] Interactive client.conf configuration ───────────────────────────

configure_client_conf() {
    local conf="${INSTALL_DIR}/airsnitch/research/client.conf"
    [[ ! -f "${conf}" ]] && return

    echo ""
    echo -e "${CYAN}${BOLD}━━━ Target Network Configuration ━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    read -r -p "$(echo -e "  Configure target network now? ${BOLD}[y/N]${NC}: ")" _confirm
    case "${_confirm}" in
        [yY]|[yY][eE][sS]) ;;
        *)
            info "Skipping — edit client.conf manually before running tests:"
            echo -e "    ${CYAN}${conf}${NC}"
            return ;;
    esac

    echo -e "  (You can re-edit at any time: ${CYAN}nano ${conf}${NC})"

    # Retry loop — user can go back and re-enter if they made a mistake
    while true; do
        echo ""
        read -r -p "  Target network SSID: " _ssid
        read -r -s -p "  Target network password/PSK: " _psk; echo ""
        echo ""

        # Auto-detect channel by scanning for the entered SSID
        # Entire block runs with set -e suspended so no scan failure can kill the script
        local _scan_iface="" _detected_freq="" _detected_chan=""
        set +e
        if [[ -n "${CONFIGURED_IFACES}" ]]; then
            _scan_iface="${CONFIGURED_IFACES%% *}"
        else
            _scan_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')
        fi
        if [[ -n "${_scan_iface}" && -n "${_ssid}" ]]; then
            echo -e "  Scanning for ${CYAN}${_ssid}${NC} on ${_scan_iface}… (may take a few seconds)"
            local _scan_out=""
            _scan_out=$(iw dev "${_scan_iface}" scan 2>/dev/null)
            if [[ -n "${_scan_out}" ]]; then
                _detected_freq=$(echo "${_scan_out}" | awk -v ssid="${_ssid}" '
                    /^[[:space:]]+freq:/ { freq = int($2) }
                    /^[[:space:]]+SSID: / {
                        s = substr($0, index($0, "SSID: ") + 6)
                        if (s == ssid) { print freq; exit }
                    }
                ')
            fi
        fi
        set -e

        # Map detected frequency to standard channel number
        if [[ -n "${_detected_freq}" ]]; then
            case "${_detected_freq}" in
                2412) _detected_chan=1  ;; 2417) _detected_chan=2  ;; 2422) _detected_chan=3  ;;
                2427) _detected_chan=4  ;; 2432) _detected_chan=5  ;; 2437) _detected_chan=6  ;;
                2442) _detected_chan=7  ;; 2447) _detected_chan=8  ;; 2452) _detected_chan=9  ;;
                2457) _detected_chan=10 ;; 2462) _detected_chan=11 ;;
                5180) _detected_chan=36 ;; 5200) _detected_chan=40 ;;
                5220) _detected_chan=44 ;; 5240) _detected_chan=48 ;;
            esac
        fi

        if [[ -n "${_detected_chan}" ]]; then
            echo -e "  Found ${CYAN}${_ssid}${NC} → channel ${CYAN}${_detected_chan}${NC} (${_detected_freq} MHz)"
            read -r -p "$(echo -e "  Target channel ${BLUE}[press Enter to accept ${_detected_chan}, or type to override]${NC}: ")" _chan
            _chan="${_chan:-${_detected_chan}}"
        else
            [[ -n "${_detected_freq}" ]] && \
                echo -e "  Found ${CYAN}${_ssid}${NC} at ${_detected_freq} MHz — no standard channel mapping"
            [[ -z "${_detected_freq}" && -n "${_scan_iface}" ]] && \
                echo -e "  ${CYAN}${_ssid}${NC} not found in scan — enter channel manually"
            echo -e "  Ch 1=2412  Ch 6=2437  Ch 11=2462  Ch 36=5180  Ch 40=5200  Ch 44=5220  Ch 48=5240"
            read -r -p "  Target channel [blank = 1 / 2412]: " _chan
        fi

        echo ""
        echo -e "  ${BOLD}Please confirm your entries:${NC}"
        echo -e "    SSID     : ${CYAN}${_ssid}${NC}"
        echo -e "    Password : ${CYAN}$(printf '%*s' "${#_psk}" | tr ' ' '*')${NC}"
        echo -e "    Channel  : ${CYAN}${_chan:-1}${NC}"
        echo ""
        read -r -p "$(echo -e "  Looks good? ${BOLD}[y/N — press N to re-enter]${NC}: ")" _ok
        case "${_ok}" in
            [yY]|[yY][eE][sS]) break ;;
            *) echo -e "  ${CYAN}Starting over — re-enter your details below.${NC}" ;;
        esac
    done

    local _freq=2412
    case "${_chan}" in
        1)  _freq=2412 ;; 2)  _freq=2417 ;; 3)  _freq=2422 ;; 4)  _freq=2427 ;;
        5)  _freq=2432 ;; 6)  _freq=2437 ;; 7)  _freq=2442 ;; 8)  _freq=2447 ;;
        9)  _freq=2452 ;; 10) _freq=2457 ;; 11) _freq=2462 ;;
        36) _freq=5180 ;; 40) _freq=5200 ;; 44) _freq=5220 ;; 48) _freq=5240 ;;
        *)  warn "Unrecognised channel '${_chan}' — defaulting to 2412 (Ch 1)" ;;
    esac

    sed -i "s/ssid=\"testnetwork\"/ssid=\"${_ssid}\"/g"  "${conf}"
    sed -i "s/psk=\"abcdefgh\"/psk=\"${_psk}\"/g"        "${conf}"
    sed -i "s/scan_freq=2412/scan_freq=${_freq}/g"        "${conf}"

    success "client.conf configured: SSID=${_ssid} on freq=${_freq} (Ch ${_chan:-1})"
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
    # Already have a monitor interface? ({ grep || true; } keeps pipefail from killing the pipe on no-match)
    local mon_iface
    mon_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | { grep -E 'mon$' || true; } | head -1)
    if [[ -n "${mon_iface}" ]]; then
        echo "[+] Monitor interface already active: ${mon_iface}"
        export AIRSNITCH_MON_IFACE="${mon_iface}"
        return 0
    fi

    # Find first non-monitor wireless interface
    local base_iface
    base_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | { grep -vE 'mon$' || true; } | head -1)
    if [[ -z "${base_iface}" ]]; then
        echo "[!] No wireless interfaces found — plug in your adapter and retry."
        return 0
    fi

    echo "[*] No monitor interface detected. Setting up monitor mode on ${base_iface}..."
    airmon-ng check kill > /dev/null 2>&1 || true
    airmon-ng start "${base_iface}" > /dev/null 2>&1 || true

    mon_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | { grep -E 'mon$' || true; } | head -1)
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

    # [FIX 11] airsnitch-run — single command to run the CLI attack tool:
    #   • validates client.conf is not still set to defaults
    #   • auto-creates a monitor interface if one is not already present
    #   • runs airsnitch.py via the venv python with the correct argument order
    cat > /usr/local/bin/airsnitch-run << 'RUNEOF'
#!/usr/bin/env bash
# airsnitch-run — one-command launcher for the AirSnitch CLI attack tool.
# Must be run as root (raw socket access required).
#
# Auto-detects the target network's frequencies via a live scan and builds
# a temporary config — no manual freq_list editing required.
set -euo pipefail

RESEARCH_DIR="/opt/airsnitch/airsnitch/research"
CONF="${RESEARCH_DIR}/client.conf"

# Sanity: refuse to run with unedited defaults
if grep -q 'ssid="testnetwork"' "${CONF}" 2>/dev/null; then
    echo ""
    echo "[!] client.conf still contains the default placeholder values."
    echo "    Edit it first, then re-run airsnitch-run:"
    echo "    nano ${CONF}"
    echo ""
    exit 1
fi

# Require root
if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

# ── Find base wireless interface (skip airmon-ng entirely) ────────────────────
# Optional $1 argument: explicitly specify the interface (used by web GUI).
# Without $1: auto-detect — skip monitor interfaces (wpa_supplicant cannot
# set wlan0mon to STATION mode, causing "Unable to connect to control interface").
if [[ -n "${1:-}" ]] && [[ "${1:-}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    IFACE="${1}"
    # Strip monitor-mode suffix — wpa_supplicant cannot use monitor interfaces
    if [[ "${IFACE}" =~ mon$ ]]; then
        IFACE="${IFACE%mon}"
        echo "[*] Stripping monitor suffix → using ${IFACE} (base interface)"
    else
        echo "[*] Interface: ${IFACE} (specified)"
    fi
else
    IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' \
        | { grep -vE 'mon$' || true; } | head -1)

    if [[ -z "${IFACE}" ]]; then
        MON_IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' \
            | { grep -E 'mon$' || true; } | head -1)
        if [[ -n "${MON_IFACE}" ]]; then
            IFACE="${MON_IFACE%mon}"
            echo "[*] Removing monitor interface ${MON_IFACE} — using ${IFACE} directly"
            iw dev "${MON_IFACE}" del 2>/dev/null || true
            sleep 1
            ip link set "${IFACE}" up 2>/dev/null || true
        fi
    fi

    if [[ -z "${IFACE}" ]]; then
        echo "[!] No wireless interfaces found. Plug in your adapter and retry."
        exit 1
    fi
fi

# ── Release interface from NetworkManager ────────────────────────────────────
nmcli device set "${IFACE}" managed no 2>/dev/null || true
trap 'nmcli device set "${IFACE}" managed yes 2>/dev/null || true' EXIT

# ── Try to create a virtual interface for dual-interface GTK check ────────────
# Some adapters (e.g. MT7612U) cannot run two wpa_supplicant instances on the
# same interface simultaneously — the driver rejects the second authentication.
# Creating a second virtual managed interface gives each connection its own
# driver state. Falls back to --same-bss mode if the adapter doesn't support it.
IFACE2=""
IFACE2_NAME="${IFACE}_gtk"
iw dev "${IFACE2_NAME}" del 2>/dev/null || true  # remove leftover from previous run
if iw dev "${IFACE}" interface add "${IFACE2_NAME}" type managed 2>/dev/null; then
    ip link set "${IFACE2_NAME}" up 2>/dev/null || true
    nmcli device set "${IFACE2_NAME}" managed no 2>/dev/null || true
    IFACE2="${IFACE2_NAME}"
    echo "[+] Dual-interface mode: victim=${IFACE}  attacker=${IFACE2}"
else
    echo "[!] Could not create virtual interface — using single-interface (--same-bss) mode"
fi

# ── Read target SSID and PSK from client.conf ────────────────────────────────
TARGET_SSID=$(grep -v '^\s*#' "${CONF}" | grep 'ssid=' | head -1 \
    | sed 's/.*ssid="\(.*\)"/\1/')
TARGET_PSK=$(grep -v '^\s*#' "${CONF}" | grep 'psk=' | head -1 \
    | sed 's/.*psk="\(.*\)"/\1/')
CTRL_IFACE=$(grep 'ctrl_interface=' "${CONF}" | head -1 \
    | sed 's/ctrl_interface=//')

# ── Scan: find BSSID+frequency pairs for the target SSID ─────────────────────
echo "[*] Scanning for '${TARGET_SSID}' on ${IFACE}..."
ip link set "${IFACE}" up 2>/dev/null || true
SCAN_RAW=$(iw dev "${IFACE}" scan 2>/dev/null || true)

# Use int() to strip decimal points (iw sometimes outputs "2412.0" not "2412")
SCAN_DETAIL=$(echo "${SCAN_RAW}" | awk -v target="${TARGET_SSID}" '
    /^BSS /        { bssid = $2; sub(/\(.*/, "", bssid); freq = "" }
    /^\s+freq:/    { freq = int($2) }
    /^\s+SSID: /   {
        ssid = substr($0, index($0, "SSID: ") + 6)
        if (ssid == target && freq != "") print bssid "\t" freq
    }
')

if [[ -z "${SCAN_DETAIL}" ]]; then
    echo "[!] '${TARGET_SSID}' not found — check adapter is up and in range."
    echo "    Falling back to all 2.4GHz channels."
    TARGET_BSSID=""
    TARGET_FREQ="2412"
    FREQ_LIST="2412 2417 2422 2427 2432 2437 2442 2447 2452 2457 2462"
else
    BEST=$(echo "${SCAN_DETAIL}" | awk '$2 >= 2400 && $2 < 3000 {print; exit}')
    if [[ -z "${BEST}" ]]; then
        BEST=$(echo "${SCAN_DETAIL}" | awk 'NR==1')
        echo "[!] No 2.4GHz AP found — using 5GHz (may be less stable for rapid reconnects)."
    fi
    TARGET_BSSID=$(echo "${BEST}" | awk '{print $1}')
    TARGET_FREQ=$(echo "${BEST}"  | awk '{print $2}')
    FREQ_LIST="${TARGET_FREQ}"
    echo "[+] '${TARGET_SSID}' found at ${TARGET_BSSID} (${TARGET_FREQ} MHz)"
fi

# ── Write temporary client.conf (never modifies the user's client.conf) ───────
TEMP_CONF=$(mktemp /tmp/airsnitch-client.XXXXXX.conf)
trap '
    rm -f "${TEMP_CONF}" 2>/dev/null || true
    nmcli device set "${IFACE}" managed yes 2>/dev/null || true
    if [[ -n "${IFACE2:-}" ]]; then
        iw dev "${IFACE2}" del 2>/dev/null || true
        nmcli device set "${IFACE2}" managed yes 2>/dev/null || true
    fi
' EXIT

if [[ -n "${IFACE2}" && -n "${TARGET_BSSID}" ]]; then
    # Dual-interface mode: pin both connections to the same AP via bssid=
    # (bssid= is only valid here — it conflicts with --same-bss in single-interface mode)
    cat > "${TEMP_CONF}" << CONFEOF
# Generated by airsnitch-run — edit ${CONF} to change SSID/PSK.
# Don't change this line, otherwise AirSnitch won't work
ctrl_interface=${CTRL_IFACE:-wpaspy_ctrl}

network={
        # Don't change this line, otherwise AirSnitch won't work
        id_str="victim"

        ssid="${TARGET_SSID}"
        bssid=${TARGET_BSSID}
        key_mgmt=WPA-PSK
        psk="${TARGET_PSK}"

        scan_freq=${TARGET_FREQ}
        freq_list=${FREQ_LIST}
}

network={
        # Don't change this line, otherwise AirSnitch won't work
        id_str="attacker"

        ssid="${TARGET_SSID}"
        bssid=${TARGET_BSSID}
        key_mgmt=WPA-PSK
        psk="${TARGET_PSK}"

        scan_freq=${TARGET_FREQ}
        freq_list=${FREQ_LIST}
}
CONFEOF
else
    # Single-interface --same-bss mode: no bssid= (conflicts with --same-bss)
    cat > "${TEMP_CONF}" << CONFEOF
# Generated by airsnitch-run — edit ${CONF} to change SSID/PSK.
# Don't change this line, otherwise AirSnitch won't work
ctrl_interface=${CTRL_IFACE:-wpaspy_ctrl}

network={
        # Don't change this line, otherwise AirSnitch won't work
        id_str="victim"

        ssid="${TARGET_SSID}"
        key_mgmt=WPA-PSK
        psk="${TARGET_PSK}"

        scan_freq=${TARGET_FREQ}
        freq_list=${FREQ_LIST}
}

network={
        # Don't change this line, otherwise AirSnitch won't work
        id_str="attacker"

        ssid="${TARGET_SSID}"
        key_mgmt=WPA-PSK
        psk="${TARGET_PSK}"

        scan_freq=${TARGET_FREQ}
        freq_list=${FREQ_LIST}
}
CONFEOF
fi

echo "[+] Using interface: ${IFACE}"
echo "[*] Starting AirSnitch — press Ctrl+C to stop."
echo ""

cd "${RESEARCH_DIR}"
if [[ -n "${IFACE2}" ]]; then
    exec venv/bin/python3 ./airsnitch.py "${IFACE}" \
        --config "${TEMP_CONF}" \
        --check-gtk-shared "${IFACE2}"
else
    exec venv/bin/python3 ./airsnitch.py "${IFACE}" \
        --config "${TEMP_CONF}" \
        --check-gtk-shared "${IFACE}" \
        --same-bss
fi
RUNEOF
    chmod +x /usr/local/bin/airsnitch-run

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
    read -r -p "$(echo -e "  Web UI port ${BLUE}[default: ${PORT} — press Enter to accept, or type a custom port]${NC}: ")" _input
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
        local detected_str="${detected[*]}"
        echo -e "  Detected wireless interfaces: ${CYAN}${detected_str}${NC}"
        read -r -p "$(echo -e "  Interfaces to release from NetworkManager ${BLUE}[press Enter to use detected: ${detected_str}]${NC}: ")" _input
        CONFIGURED_IFACES="${_input:-${detected_str}}"
    else
        echo -e "  ${CYAN}No wireless interfaces detected yet — you can still enter names manually.${NC}"
        read -r -p "$(echo -e "  Interfaces to release from NetworkManager ${BLUE}[e.g. wlan1 wlan2, blank to skip]${NC}: ")" _input
        CONFIGURED_IFACES="${_input:-}"
    fi

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
    configure_client_conf

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
    echo -e "  ${BOLD}Start the web UI (recommended):${NC}"
    echo -e "    ${CYAN}sudo airsnitch-web${NC}"
    echo -e "    Then open ${CYAN}http://localhost:${PORT}${NC} in your browser"
    echo ""
    echo -e "  ${BOLD}Run the CLI attack directly (advanced):${NC}"
    echo -e "    ${CYAN}sudo airsnitch-run${NC}"
    echo -e "  Handles monitor mode, venv, and argument order automatically."
    echo -e "  Edit client.conf first if you skipped the setup wizard:"
    echo -e "    ${CYAN}nano /opt/airsnitch/airsnitch/research/client.conf${NC}"
    echo ""
    echo -e "  ${BOLD}With NetworkManager interface release:${NC}"
    echo -e "    ${CYAN}sudo AIRSNITCH_IFACES=\"wlan1 wlan2\" airsnitch-web${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}━━━ Important operational notes ━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # ARM64 warning
    local arch
    arch=$(uname -m)
    if [[ "${arch}" == "aarch64" || "${arch}" == "arm64" ]]; then
        echo -e "  ${YELLOW}[ARM64 DETECTED]${NC} The web UI 'Monitor Mode' button may not work"
        echo -e "  reliably on ARM64. ${BOLD}airsnitch-run${NC} handles this automatically."
        echo -e "  If you need to set monitor mode manually:"
        echo -e "    ${CYAN}airmon-ng check kill${NC}"
        echo -e "    ${CYAN}airmon-ng start <iface>${NC}   # creates <iface>mon e.g. wlan0mon"
        echo ""
    fi

    echo -e "  ${BOLD}Do NOT use 'sudo ./airsnitch.py' directly:${NC}"
    echo -e "  sudo drops the venv → 'No module named Crypto'."
    echo -e "  Use ${CYAN}airsnitch-run${NC} or the venv python explicitly:"
    echo -e "    ${CYAN}cd /opt/airsnitch/airsnitch/research${NC}"
    echo -e "    ${CYAN}venv/bin/python3 ./airsnitch.py <iface> --config client.conf --check-gtk-shared <iface>${NC}"
    echo ""
    echo -e "  ${BOLD}client.conf:${NC} set ssid, psk, and scan_freq in BOTH network{} blocks."
    echo -e "  Channel → frequency: Ch 1=2412  Ch 6=2437  Ch 11=2462  Ch 36=5180  Ch 40=5200"
    echo -e "  (Run ${CYAN}airodump-ng <iface>mon${NC} to find your target's channel.)"
    echo ""
    echo -e "  ${BOLD}Web UI Terminal tab:${NC} click Connect for a root shell in the browser."
    echo ""
}

main "$@"

