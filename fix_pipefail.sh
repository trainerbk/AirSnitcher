#!/usr/bin/env bash
# Fixes pipefail bug in start.sh and airsnitch-run:
# grep returning exit code 1 (no monitor iface) was killing the pipeline.

for f in /opt/airsnitch/start.sh /usr/local/bin/airsnitch-run; do
    sed -i "s/grep -E 'mon\$' | head -1 || true/{ grep -E 'mon\$' || true; } | head -1/g" "$f"
    sed -i "s/grep -vE 'mon\$' | head -1 || true/{ grep -vE 'mon\$' || true; } | head -1/g" "$f"
    echo "patched: $f"
done

echo ""
echo "Verify (should show '{ grep' not '|| true)' at end):"
grep "grep.*mon" /opt/airsnitch/start.sh /usr/local/bin/airsnitch-run
echo ""
echo "Done. Now run: sudo airsnitch-web"
