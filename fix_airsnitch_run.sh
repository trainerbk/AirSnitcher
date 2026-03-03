#!/usr/bin/env bash
# Fixes airsnitch-run to use the base wireless interface (e.g. wlan0) directly
# instead of creating wlan0mon with airmon-ng.
#
# Root cause: airmon-ng's virtual wlan0mon interface cannot be set to STATION
# mode by wpa_supplicant, causing "Unable to connect to control interface".
# airsnitch's modified wpa_supplicant manages the interface mode internally.

TARGET=/usr/local/bin/airsnitch-run

cat > "${TARGET}" << 'EOF'
#!/usr/bin/env bash
# airsnitch-run — one-command launcher for the AirSnitch CLI attack tool.
# Must be run as root (raw socket access required).
set -euo pipefail

RESEARCH_DIR="/opt/airsnitch/airsnitch/research"
CONF="${RESEARCH_DIR}/client.conf"

# Sanity: refuse to run with unedited defaults
if grep -q 'ssid="testnetwork"' "${CONF}" 2>/dev/null; then
    echo ""
    echo "[!] client.conf still contains the default placeholder values."
    echo "    Edit it first, then re-run airsnitch-run:"
    echo ""
    echo "    nano ${CONF}"
    echo ""
    echo "    Set ssid, psk, and scan_freq in BOTH network{} blocks."
    echo ""
    exit 1
fi

# Require root
if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

# airsnitch's modified wpa_supplicant manages the interface mode internally —
# it does NOT need a monitor interface from airmon-ng. Use the base interface.
# If only wlan0mon exists (leftover from airmon-ng), remove it first.
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

echo "[+] Using interface: ${IFACE}"
echo "[*] Starting AirSnitch — press Ctrl+C to stop."
echo ""

cd "${RESEARCH_DIR}"
exec venv/bin/python3 ./airsnitch.py "${IFACE}" \
    --config client.conf \
    --check-gtk-shared "${IFACE}"
EOF

chmod +x "${TARGET}"
echo "[+] Fixed: ${TARGET}"
echo ""
echo "Now run: sudo airsnitch-run"
