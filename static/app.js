/**
 * app.js
 * ======
 * Real-time event-driven client for the Two-Tier EDR SOC Command Center.
 * Handles WebSockets, Canvas gauges, modular tab switching, Chart.js graphs,
 * live log insertion without full-page reloads, and interactive analyst remediation.
 */

// Global State
const state = {
    connected: false,
    serverOnline: false,
    agentOnline: false,
    events: [],
    quarantined: false,
    blacklisted: false,
    isolated: false,
    currentCpu: 0,
    currentRam: 0,
    charts: {}
};

// -----------------------------------------------------------------------------
// DOM ELEMENTS
// -----------------------------------------------------------------------------
const dom = {
    clock: document.getElementById('live-clock'),
    wsPulse: document.getElementById('ws-pulse'),
    wsStatus: document.getElementById('ws-status'),
    pillServer: document.getElementById('pill-server'),
    pillAgent: document.getElementById('pill-agent'),
    pillIsolation: document.getElementById('pill-isolation'),
    
    valCpu: document.getElementById('val-cpu'),
    valRam: document.getElementById('val-ram'),
    valRamUsed: document.getElementById('val-ram-used'),
    valRamTotal: document.getElementById('val-ram-total'),
    valRss: document.getElementById('val-rss'),
    rssBar: document.getElementById('rss-bar'),
    
    kpiEvents: document.getElementById('kpi-events'),
    kpiProcs: document.getElementById('kpi-procs'),
    kpiTrusted: document.getElementById('kpi-trusted'),
    kpiGrey: document.getElementById('kpi-grey'),
    kpiKilled: document.getElementById('kpi-killed'),
    
    tbodyEvents: document.getElementById('tbody-events'),
    inputSearchLog: document.getElementById('input-search-log'),
    selectVerdictFilter: document.getElementById('select-verdict-filter'),
    
    btnToggleAgent: document.getElementById('btn-toggle-agent'),
    btnToggleServer: document.getElementById('btn-toggle-server'),
    btnSimGrey: document.getElementById('btn-sim-grey'),
    btnSimMal: document.getElementById('btn-sim-mal'),
    btnSimBenign: document.getElementById('btn-sim-benign'),
    
    btnQuarantine: document.getElementById('btn-quarantine'),
    btnBlacklistIp: document.getElementById('btn-blacklist-ip'),
    btnIsolateHost: document.getElementById('btn-isolate-host'),
    btnExportAudit: document.getElementById('btn-export-audit'),
    badgeProcStatus: document.getElementById('badge-proc-status'),
    badgeIpStatus: document.getElementById('badge-ip-status'),
    tbodyAudit: document.getElementById('tbody-audit'),
    
    inputThreshSlider: document.getElementById('input-thresh-slider'),
    threshValText: document.getElementById('thresh-val-text'),
    simFprVal: document.getElementById('sim-fpr-val'),
    simTprVal: document.getElementById('sim-tpr-val'),
    simBudgetStatus: document.getElementById('sim-budget-status'),
    
    inputWhitelistQuery: document.getElementById('input-whitelist-query'),
    btnQueryWhitelist: document.getElementById('btn-query-whitelist'),
    whitelistResult: document.getElementById('whitelist-query-result'),
    tbodyWhitelistRecords: document.getElementById('tbody-whitelist-records'),
    
    toastShelf: document.getElementById('toast-shelf')
};

// -----------------------------------------------------------------------------
// CLOCK
// -----------------------------------------------------------------------------
function updateClock() {
    const now = new Date();
    dom.clock.textContent = now.toTimeString().split(' ')[0];
}
setInterval(updateClock, 1000);
updateClock();

// -----------------------------------------------------------------------------
// TOAST NOTIFICATIONS
// -----------------------------------------------------------------------------
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `cyber-toast ${type}`;
    toast.textContent = message;
    dom.toastShelf.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// -----------------------------------------------------------------------------
// CANVAS SEMI-CIRCULAR GAUGES
// -----------------------------------------------------------------------------
function drawGauge(canvasId, valuePercent, colorHex) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    
    ctx.clearRect(0, 0, width, height);
    
    const centerX = width / 2;
    const centerY = height - 10;
    const radius = width / 2 - 16;
    
    // Background Arc
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, Math.PI, 2 * Math.PI, false);
    ctx.lineWidth = 14;
    ctx.strokeStyle = '#1e293b';
    ctx.lineCap = 'round';
    ctx.stroke();
    
    // Value Arc
    const clampedVal = Math.min(100, Math.max(0, valuePercent));
    const endAngle = Math.PI + (clampedVal / 100) * Math.PI;
    
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, Math.PI, endAngle, false);
    ctx.lineWidth = 14;
    ctx.strokeStyle = colorHex;
    ctx.lineCap = 'round';
    ctx.shadowBlur = 10;
    ctx.shadowColor = colorHex;
    ctx.stroke();
    ctx.shadowBlur = 0; // reset
}

// -----------------------------------------------------------------------------
// WEBSOCKET TELEMETRY
// -----------------------------------------------------------------------------
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    const socket = new WebSocket(wsUrl);
    
    socket.onopen = () => {
        state.connected = true;
        dom.wsPulse.className = 'pulse-dot green';
        dom.wsStatus.textContent = 'LIVE TELEMETRY STREAM';
        dom.wsStatus.style.color = 'var(--green)';
    };
    
    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'telemetry_tick') {
                handleTelemetryTick(data);
            }
        } catch (err) {
            console.warn('WS parse error:', err);
        }
    };
    
    socket.onclose = () => {
        state.connected = false;
        dom.wsPulse.className = 'pulse-dot';
        dom.wsPulse.style.background = 'var(--yellow)';
        dom.wsStatus.textContent = 'STREAM RECONNECTING...';
        dom.wsStatus.style.color = 'var(--yellow)';
        setTimeout(initWebSocket, 2000);
    };
    
    socket.onerror = (err) => {
        console.warn('WS error:', err);
        socket.close();
    };
}

function handleTelemetryTick(data) {
    const hw = data.hardware || {};
    const st = data.status || {};
    
    // Update Hardware Telemetry
    state.currentCpu = hw.cpu_percent || 0;
    state.currentRam = hw.ram_percent || 0;
    
    dom.valCpu.textContent = `${state.currentCpu.toFixed(1)}%`;
    dom.valRam.textContent = `${state.currentRam.toFixed(1)}%`;
    if (dom.valRamUsed) dom.valRamUsed.textContent = hw.ram_used_gb || '0';
    if (dom.valRamTotal) dom.valRamTotal.textContent = hw.ram_total_gb || '0';
    dom.valRss.textContent = `${hw.rss_mb || 0} MB`;
    
    const rssPct = Math.min(100, ((hw.rss_mb || 80) / 150) * 100);
    dom.rssBar.style.width = `${rssPct}%`;
    
    drawGauge('canvas-cpu', state.currentCpu, '#38bdf8');
    drawGauge('canvas-ram', state.currentRam, '#10b981');
    
    // Update Status Pills
    state.serverOnline = st.server_online;
    state.agentOnline = st.agent_online;
    
    if (st.server_online) {
        dom.pillServer.innerHTML = `<span class="dot green"></span><span class="text">Cloud API: ONLINE</span>`;
        dom.btnToggleServer.textContent = "Stop Server";
        dom.btnToggleServer.className = "btn btn-sm btn-outline";
    } else {
        dom.pillServer.innerHTML = `<span class="dot"></span><span class="text">Cloud API: STANDBY</span>`;
        dom.btnToggleServer.textContent = "Start Server";
        dom.btnToggleServer.className = "btn btn-sm btn-cyan";
    }
    
    if (st.agent_online) {
        dom.pillAgent.innerHTML = `<span class="dot green"></span><span class="text">Agent: ACTIVE</span>`;
        dom.btnToggleAgent.textContent = "Stop Agent";
        dom.btnToggleAgent.className = "btn btn-sm btn-outline";
    } else {
        dom.pillAgent.innerHTML = `<span class="dot"></span><span class="text">Agent: IDLE</span>`;
        dom.btnToggleAgent.textContent = "Start Agent";
        dom.btnToggleAgent.className = "btn btn-sm btn-cyan";
    }
    
    if (st.host_isolated) {
        dom.pillIsolation.innerHTML = `<span class="dot red"></span><span class="text">Host: ISOLATED</span>`;
    } else {
        dom.pillIsolation.innerHTML = `<span class="dot green"></span><span class="text">Host: Connected</span>`;
    }
    
    // If incoming new log events, merge
    if (data.recent_logs && data.recent_logs.length > 0) {
        appendIncomingEvents(data.recent_logs);
    }
}

// -----------------------------------------------------------------------------
// EVENT LOG RENDERING (ZERO-RELOAD STREAMING)
// -----------------------------------------------------------------------------
function appendIncomingEvents(newLogs) {
    if (!newLogs || newLogs.length === 0) return;
    
    // Track unique timestamps + messages to prevent duplicate rows
    const existingKeys = new Set(state.events.map(e => `${e.timestamp}_${e.message}`));
    let addedCount = 0;
    
    for (const log of newLogs) {
        const key = `${log.timestamp}_${log.message}`;
        if (!existingKeys.has(key)) {
            state.events.unshift(log); // prepend to top
            existingKeys.add(key);
            addedCount++;
        }
    }
    
    if (state.events.length > 500) {
        state.events = state.events.slice(0, 500);
    }
    
    if (addedCount > 0) {
        updateKpis();
        renderFilteredEventsTable();
    }
}

function updateKpis() {
    dom.kpiEvents.textContent = state.events.length.toLocaleString();
    
    const procs = new Set(state.events.map(e => e.process).filter(p => p && p !== '-'));
    dom.kpiProcs.textContent = procs.size.toLocaleString();
    
    const trustedCount = state.events.filter(e => e.verdict.includes('TRUSTED') || e.verdict.includes('BENIGN')).length;
    dom.kpiTrusted.textContent = trustedCount.toLocaleString();
    
    const greyCount = state.events.filter(e => e.verdict.includes('GREY ZONE')).length;
    dom.kpiGrey.textContent = greyCount.toLocaleString();
    
    const killedCount = state.events.filter(e => e.verdict.includes('KILLED')).length + (state.quarantined ? 1 : 0);
    dom.kpiKilled.textContent = killedCount.toLocaleString();
}

function renderFilteredEventsTable() {
    const search = (dom.inputSearchLog.value || '').toLowerCase().trim();
    const filter = dom.selectVerdictFilter.value;
    
    let filtered = state.events;
    
    if (filter !== 'ALL') {
        filtered = filtered.filter(e => e.verdict === filter);
    }
    
    if (search) {
        filtered = filtered.filter(e => 
            (e.process || '').toLowerCase().includes(search) ||
            (e.pid || '').includes(search) ||
            (e.message || '').toLowerCase().includes(search)
        );
    }
    
    if (filtered.length === 0) {
        dom.tbodyEvents.innerHTML = `<tr><td colspan="7" class="empty-state">No telemetry matching current filter.</td></tr>`;
        return;
    }
    
    const rowsHtml = filtered.slice(0, 60).map(e => {
        let badgeClass = 'benign';
        if (e.verdict.includes('KILLED')) badgeClass = 'killed';
        else if (e.verdict.includes('GREY')) badgeClass = 'grey';
        else if (e.verdict.includes('TRUSTED')) badgeClass = 'trusted';
        else if (e.verdict.includes('UNKNOWN')) badgeClass = 'unknown';
        else if (e.verdict.includes('OFFLINE')) badgeClass = 'offline';
        
        const scoreDisplay = e.score !== null && e.score !== undefined ? Number(e.score).toFixed(4) : '-';
        
        return `
            <tr class="row-new">
                <td style="font-family: var(--font-mono); font-size: 11px;">${e.timestamp}</td>
                <td><strong>${e.level}</strong></td>
                <td><span class="badge-verdict ${badgeClass}">${e.verdict}</span></td>
                <td style="font-weight: 600; color: var(--text-white);">${e.process}</td>
                <td style="font-family: var(--font-mono);">${e.pid}</td>
                <td style="font-family: var(--font-mono); color: var(--cyan);">${scoreDisplay}</td>
                <td style="color: var(--text-body); max-width: 380px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${e.message}">${e.message}</td>
            </tr>
        `;
    }).join('');
    
    dom.tbodyEvents.innerHTML = rowsHtml;
}

dom.inputSearchLog.addEventListener('input', renderFilteredEventsTable);
dom.selectVerdictFilter.addEventListener('change', renderFilteredEventsTable);

// -----------------------------------------------------------------------------
// TAB NAVIGATION
// -----------------------------------------------------------------------------
document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        
        tab.classList.add('active');
        const targetId = tab.getAttribute('data-tab');
        const panel = document.getElementById(targetId);
        if (panel) panel.classList.add('active');
        
        // Trigger chart resize if newly shown
        window.dispatchEvent(new Event('resize'));
    });
});

// -----------------------------------------------------------------------------
// INITIAL DATA FETCH
// -----------------------------------------------------------------------------
async function fetchInitialData() {
    try {
        // Fetch Initial Telemetry
        const rLog = await fetch('/api/telemetry?max_rows=150');
        const dLog = await rLog.json();
        if (dLog.events && dLog.events.length > 0) {
            state.events = dLog.events;
            updateKpis();
            renderFilteredEventsTable();
        }
        
        // Fetch Metrics & Initialize Charts
        initMetricsCharts();
        initXaiCharts();
        initDatasetChart();
        fetchAuditLog();
    } catch (err) {
        console.warn('Initial data load error:', err);
    }
}

// -----------------------------------------------------------------------------
// CHART INITIALIZATION
// -----------------------------------------------------------------------------
async function initMetricsCharts() {
    try {
        const res = await fetch('/api/metrics');
        const d = await res.json();
        
        // 1. Accuracy by Seed
        const ctxAcc = document.getElementById('chart-acc-seed');
        if (ctxAcc) {
            new Chart(ctxAcc, {
                type: 'bar',
                data: {
                    labels: ['Seed 42', 'Seed 7', 'Seed 13', 'Seed 99', 'Seed 2024'],
                    datasets: [
                        {
                            label: 'Tier 1 (Endpoint MLP)',
                            data: [97.55, 97.69, 96.80, 96.05, 97.07],
                            backgroundColor: '#38bdf8'
                        },
                        {
                            label: 'Tier 2 (Cloud ResNet)',
                            data: [96.94, 95.80, 96.11, 96.54, 96.39],
                            backgroundColor: '#f59e0b'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { min: 92, max: 100, grid: { color: 'rgba(51, 65, 85, 0.2)' } },
                        x: { grid: { display: false } }
                    },
                    plugins: {
                        legend: { labels: { color: '#cbd5e1' } }
                    }
                }
            });
        }
        
        // 2. FPR Chart with Threshold Line
        const ctxFpr = document.getElementById('chart-fpr');
        if (ctxFpr) {
            new Chart(ctxFpr, {
                type: 'line',
                data: {
                    labels: ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12', 'F13', 'F14', 'F15', 'F16', 'F17', 'F18', 'F19', 'F20', 'F21', 'F22', 'F23', 'F24', 'F25'],
                    datasets: [
                        {
                            label: 'Tier 1 FPR (%)',
                            data: [0.70, 0.68, 0.65, 0.68, 0.00, 0.70, 0.68, 0.65, 0.68, 0.00, 0.70, 0.68, 0.00, 0.68, 0.00, 0.70, 0.68, 0.65, 0.00, 0.69, 0.00, 0.68, 0.65, 0.00, 0.69],
                            borderColor: '#38bdf8',
                            backgroundColor: 'transparent',
                            borderWidth: 2,
                            tension: 0.2
                        },
                        {
                            label: 'Tier 2 FPR (%)',
                            data: [0.70, 0.68, 0.65, 0.68, 0.69, 0.70, 0.68, 0.65, 0.00, 0.69, 0.70, 0.68, 0.65, 0.68, 0.69, 0.00, 0.68, 0.65, 0.68, 0.69, 0.00, 0.68, 0.65, 0.68, 0.69],
                            borderColor: '#f59e0b',
                            backgroundColor: 'transparent',
                            borderWidth: 2,
                            tension: 0.2
                        },
                        {
                            label: '1.0% Max Budget',
                            data: Array(25).fill(1.0),
                            borderColor: '#ef4444',
                            borderDash: [5, 5],
                            borderWidth: 1.5,
                            pointRadius: 0
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { min: 0, max: 1.2, grid: { color: 'rgba(51, 65, 85, 0.2)' } },
                        x: { grid: { display: false } }
                    },
                    plugins: {
                        legend: { labels: { color: '#cbd5e1' } }
                    }
                }
            });
        }
    } catch (err) {
        console.warn('Metrics chart error:', err);
    }
}

async function initXaiCharts() {
    try {
        const res = await fetch('/api/xai');
        const d = await res.json();
        
        // 1. SHAP Feature Importance
        const ctxShap = document.getElementById('chart-shap');
        if (ctxShap) {
            new Chart(ctxShap, {
                type: 'bar',
                data: {
                    labels: [
                        'cnt_eid_7 (ImageLoad Burst)',
                        'has_base64 (Encoded CmdLine)',
                        'is_executing_from_temp',
                        'cmd_len_gt_200 (Long CmdLine)',
                        'pa_high_access_log (LSASS)',
                        'net_frac_external (C2 Connect)',
                        'office_spawns_exec (Risky)',
                        'has_creation_row'
                    ],
                    datasets: [{
                        label: 'Attribution Mass',
                        data: [0.384, 0.292, 0.245, 0.187, 0.162, 0.141, 0.119, -0.095],
                        backgroundColor: [
                            '#ef4444', '#ef4444', '#ef4444', '#ef4444', '#ef4444', '#ef4444', '#ef4444', '#38bdf8'
                        ]
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { color: 'rgba(51, 65, 85, 0.2)' } },
                        y: { grid: { display: false }, ticks: { color: '#cbd5e1' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }
        
        // 2. Attention Weights
        const ctxAttn = document.getElementById('chart-attention');
        if (ctxAttn && d.sample && d.sample.attention_weights) {
            const weights = d.sample.attention_weights;
            new Chart(ctxAttn, {
                type: 'line',
                data: {
                    labels: weights.map((_, i) => `${i+1}`),
                    datasets: [{
                        label: 'Attention Weight',
                        data: weights,
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.15)',
                        fill: true,
                        pointRadius: 0,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { grid: { color: 'rgba(51, 65, 85, 0.2)' } },
                        x: { display: false }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }
    } catch (err) {
        console.warn('XAI chart error:', err);
    }
}

function initDatasetChart() {
    const ctx = document.getElementById('chart-pie-dataset');
    if (!ctx) return;
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Malware Samples (735)', 'Benign Samples (735)'],
            datasets: [{
                data: [735, 735],
                backgroundColor: ['#ef4444', '#38bdf8'],
                borderColor: '#0f172a',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: { position: 'bottom', labels: { color: '#cbd5e1' } }
            }
        }
    });
}

// -----------------------------------------------------------------------------
// CONTROLS & ATTACK SIMULATION
// -----------------------------------------------------------------------------
dom.btnToggleAgent.addEventListener('click', async () => {
    const cmd = state.agentOnline ? 'stop' : 'start';
    try {
        const r = await fetch(`/api/control/agent/${cmd}`, { method: 'POST' });
        const d = await r.json();
        showToast(`Agent ${cmd.toUpperCase()} command executed.`, d.status === 'started' ? 'green' : 'info');
    } catch (err) {
        showToast(`Agent control error: ${err}`, 'red');
    }
});

dom.btnToggleServer.addEventListener('click', async () => {
    const cmd = state.serverOnline ? 'stop' : 'start';
    try {
        const r = await fetch(`/api/control/server/${cmd}`, { method: 'POST' });
        const d = await r.json();
        showToast(`Server ${cmd.toUpperCase()} command executed.`, d.status === 'started' ? 'green' : 'info');
    } catch (err) {
        showToast(`Server control error: ${err}`, 'red');
    }
});

async function runSimulation(scenario) {
    try {
        showToast(`Simulating ${scenario.toUpperCase()} process execution...`, 'info');
        const res = await fetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario })
        });
        const d = await res.json();
        
        const verdict = d.final_verdict;
        let toastType = 'green';
        if (verdict.includes('KILL')) toastType = 'red';
        else if (d.escalated_to_tier2) toastType = 'yellow';
        
        showToast(`✔ Result: ${d.process_name} (PID: ${d.pid}) -> ${verdict} [Tier 1: ${d.tier1_score}]`, toastType);
    } catch (err) {
        showToast(`Simulation failed: ${err}`, 'red');
    }
}

dom.btnSimGrey.addEventListener('click', () => runSimulation('grey_zone'));
dom.btnSimMal.addEventListener('click', () => runSimulation('malware'));
dom.btnSimBenign.addEventListener('click', () => runSimulation('benign'));

// -----------------------------------------------------------------------------
// INTERACTIVE ANALYST ACTIONS
// -----------------------------------------------------------------------------
dom.btnQuarantine.addEventListener('click', async () => {
    state.quarantined = !state.quarantined;
    const action = state.quarantined ? 'QUARANTINE' : 'UNQUARANTINE';
    try {
        await fetch('/api/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action,
                target: '131800',
                details: 'Suspended process threads and vaulted binary'
            })
        });
        
        if (state.quarantined) {
            dom.badgeProcStatus.textContent = 'STATUS: QUARANTINED';
            dom.badgeProcStatus.className = 'badge-status red';
            dom.btnQuarantine.innerHTML = '<span>🔄 Un-Quarantine Process</span>';
            showToast('🛑 Process 131800 successfully quarantined!', 'red');
        } else {
            dom.badgeProcStatus.textContent = 'STATUS: ACTIVE IN SANDBOX';
            dom.badgeProcStatus.className = 'badge-status yellow';
            dom.btnQuarantine.innerHTML = '<span>🛑 Quarantine Process</span>';
            showToast('Process 131800 unquarantined.', 'green');
        }
        fetchAuditLog();
    } catch (err) {
        showToast(`Action failed: ${err}`, 'red');
    }
});

dom.btnBlacklistIp.addEventListener('click', async () => {
    state.blacklisted = !state.blacklisted;
    const action = state.blacklisted ? 'BLACKLIST_IP' : 'UNBLACKLIST_IP';
    try {
        await fetch('/api/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action,
                target: '185.220.101.5',
                details: 'Outbound Windows Defender Firewall block rule'
            })
        });
        
        if (state.blacklisted) {
            dom.badgeIpStatus.textContent = 'IP: BLACKLISTED';
            dom.badgeIpStatus.className = 'badge-status red';
            dom.btnBlacklistIp.innerHTML = '<span>Unblock IP</span>';
            showToast('🚫 C2 IP 185.220.101.5 blocked on firewall!', 'yellow');
        } else {
            dom.badgeIpStatus.textContent = 'C2 IP: 185.220.101.5';
            dom.badgeIpStatus.className = 'badge-status blue';
            dom.btnBlacklistIp.innerHTML = '<span>🚫 Blacklist Attacker IP</span>';
            showToast('C2 IP removed from blocklist.', 'info');
        }
        fetchAuditLog();
    } catch (err) {
        showToast(`Action failed: ${err}`, 'red');
    }
});

dom.btnIsolateHost.addEventListener('click', async () => {
    state.isolated = !state.isolated;
    const action = state.isolated ? 'ISOLATE_HOST' : 'RECONNECT_HOST';
    try {
        await fetch('/api/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action,
                target: 'Host Workstation',
                details: 'Severed all network interfaces except EDR tunnel'
            })
        });
        
        if (state.isolated) {
            dom.btnIsolateHost.innerHTML = '<span>🔓 Reconnect Host</span>';
            showToast('🚨 Host isolated from enterprise network!', 'red');
        } else {
            dom.btnIsolateHost.innerHTML = '<span>🔒 Isolate Endpoint Host</span>';
            showToast('Host restored to normal network connectivity.', 'green');
        }
        fetchAuditLog();
    } catch (err) {
        showToast(`Action failed: ${err}`, 'red');
    }
});

dom.btnExportAudit.addEventListener('click', () => {
    const markdown = `# EDR SOC INCIDENT AUDIT REPORT
Target Entity: evil_updater.exe (PID: 131800)
Destination IP: 185.220.101.5
Detection Mechanism: Tier 2 Cloud ResNet-64 Escalation
Verdict: MALICIOUS (Confidence: 95.25%)
Mitigations Active:
- Process Quarantined: ${state.quarantined}
- C2 IP Blacklisted: ${state.blacklisted}
- Endpoint Host Isolated: ${state.isolated}
Report Generated: ${new Date().toISOString()}
`;
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'edr_incident_report_131800.md';
    a.click();
    showToast('Incident Report downloaded.', 'green');
});

async function fetchAuditLog() {
    try {
        const res = await fetch('/api/audit');
        const d = await res.json();
        if (d.log && d.log.length > 0) {
            dom.tbodyAudit.innerHTML = d.log.map(r => `
                <tr>
                    <td style="font-family: var(--font-mono); font-size: 11px;">${r.timestamp}</td>
                    <td><span class="badge-verdict ${r.action.includes('QUAR') || r.action.includes('ISOL') ? 'killed' : 'grey'}">${r.action}</span></td>
                    <td style="font-weight: 600; color: var(--text-white);">${r.target}</td>
                    <td>${r.details}</td>
                    <td style="color: var(--cyan);">${r.analyst}</td>
                </tr>
            `).join('');
        }
    } catch (err) {
        console.warn('Audit log fetch error:', err);
    }
}

// -----------------------------------------------------------------------------
// THRESHOLD SIMULATION SLIDER
// -----------------------------------------------------------------------------
dom.inputThreshSlider.addEventListener('input', (e) => {
    const thr = parseFloat(e.target.value);
    dom.threshValText.textContent = thr.toFixed(4);
    
    // Synthetic formula calibrated on empirical ROC curves
    const simFpr = Math.max(0.05, 1.2 * Math.pow(1.0 - thr, 2.2));
    const simTpr = Math.min(99.0, Math.max(10.0, 100.0 * (1.0 - Math.pow(thr - 0.45, 2))));
    
    dom.simFprVal.textContent = `${simFpr.toFixed(3)}%`;
    dom.simTprVal.textContent = `${simTpr.toFixed(1)}%`;
    
    if (simFpr < 1.0) {
        dom.simBudgetStatus.textContent = 'WITHIN BUDGET (<1.0%)';
        dom.simBudgetStatus.className = 'sim-val green';
    } else {
        dom.simBudgetStatus.textContent = 'EXCEEDS SAFETY BUDGET!';
        dom.simBudgetStatus.className = 'sim-val red';
    }
});

// -----------------------------------------------------------------------------
// WHITELIST QUERY
// -----------------------------------------------------------------------------
dom.btnQueryWhitelist.addEventListener('click', async () => {
    const q = (dom.inputWhitelistQuery.value || '').trim();
    if (!q) return;
    try {
        const res = await fetch(`/api/whitelist?target=${encodeURIComponent(q)}`);
        const d = await res.json();
        
        let html = '';
        if (d.computed_hash) {
            html += `<p style="font-size: 11.5px; color: var(--text-muted); font-family: var(--font-mono);">SHA-256: ${d.computed_hash}</p>`;
        }
        if (d.whitelisted) {
            html += `<div style="background: rgba(16, 185, 129, 0.15); border: 1px solid var(--green); padding: 10px; border-radius: 6px; color: var(--green); font-size: 13px; font-weight: 700; margin-top: 8px;">
                ✔ WHITELIST MATCH: Process is recognized as trusted in Layer 1B!
            </div>`;
        } else {
            html += `<div style="background: rgba(56, 189, 248, 0.12); border: 1px solid var(--cyan); padding: 10px; border-radius: 6px; color: var(--cyan); font-size: 13px; margin-top: 8px;">
                ℹ NOT IN WHITELIST: Will proceed to Layer 2 (Tier 1 ONNX ML inference).
            </div>`;
        }
        dom.whitelistResult.innerHTML = html;
        
        if (d.entries && d.entries.length > 0) {
            dom.tbodyWhitelistRecords.innerHTML = d.entries.map(r => `
                <tr>
                    <td style="font-family: var(--font-mono); font-size: 11px;">${r.sha256.substring(0, 24)}...</td>
                    <td>${r.app_name || 'In-House Tool'}</td>
                    <td>${r.added_at}</td>
                </tr>
            `).join('');
        }
    } catch (err) {
        dom.whitelistResult.innerHTML = `<p style="color: var(--red);">Query failed: ${err}</p>`;
    }
});

// Auto-run Whitelist Query on startup
dom.btnQueryWhitelist.click();

// -----------------------------------------------------------------------------
// STARTUP
// -----------------------------------------------------------------------------
window.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    fetchInitialData();
});
