#!/usr/bin/env bash
# Fix: Setup Wizard nav button (class="nav-btn nav-wizard") has no data-tab.
# Tab click handler strips active from all sections then crashes on
# getElementById('tab-undefined'). Add early return to skip non-tab buttons.

APP=/opt/airsnitch/web/static/js/app.js

# Insert early-return guard line after the click handler opening
sed -i "/btn.addEventListener('click', () => {/a\\        if (!btn.dataset.tab) return;" "$APP"

echo "Fixed: $APP"
echo ""
echo "Verify (should see 'if (!btn.dataset.tab)' on line after addEventListener):"
grep -n "dataset.tab" "$APP" | head -5
echo ""
echo "Hard-reload the browser (Ctrl+Shift+R) to pick up the fix."
