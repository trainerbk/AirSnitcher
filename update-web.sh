#!/usr/bin/env bash
# update-web.sh — redeploy web UI files from repo to /opt/airsnitch/web/
# Run after git pull to apply UI changes without a full reinstall.
set -euo pipefail

INSTALL_DIR="/opt/airsnitch"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

echo "[*] Copying web files to ${INSTALL_DIR}/web/ ..."
cp "${SCRIPT_DIR}/web/server.py"                "${INSTALL_DIR}/web/"
cp "${SCRIPT_DIR}/web/templates/index.html"     "${INSTALL_DIR}/web/templates/"
cp "${SCRIPT_DIR}/web/static/css/style.css"     "${INSTALL_DIR}/web/static/css/"
cp "${SCRIPT_DIR}/web/static/js/app.js"         "${INSTALL_DIR}/web/static/js/"

echo "[*] Patching airsnitch-run ..."
bash "${SCRIPT_DIR}/fix_airsnitch_run.sh"

echo "[*] Restarting airsnitch-web service ..."
systemctl restart airsnitch-web 2>/dev/null || true

echo "[+] Done. Hard-refresh your browser (Ctrl+Shift+R) to pick up the new UI."
