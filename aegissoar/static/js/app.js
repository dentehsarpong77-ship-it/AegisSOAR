let ws;
let audioEnabled = false;
let audioCtx = null;
const maxTerminalLines = 80;

document.addEventListener("DOMContentLoaded", () => {
  initThreatMap();
  connectWebSocket();
  loadInitialData();
  setupEventListeners();
});

function playAlertBeep(freq = 600, duration = 0.15) {
  if (!audioEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch (e) {
    console.error("Audio error", e);
  }
}

function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/stream`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log("[AegisSOAR] Real-time telemetry WebSocket connected.");
    document.getElementById("wsStatus").innerText = "CONNECTED";
    document.getElementById("wsStatus").style.color = "#10b981";
  };

  ws.onmessage = (event) => {
    try {
      const packet = JSON.parse(event.data);
      handleWebSocketMessage(packet);
    } catch (e) {
      console.error("[AegisSOAR] WS Parse error", e);
    }
  };

  ws.onclose = () => {
    console.warn("[AegisSOAR] WebSocket disconnected. Retrying in 3s...");
    document.getElementById("wsStatus").innerText = "RECONNECTING";
    document.getElementById("wsStatus").style.color = "#f59e0b";
    setTimeout(connectWebSocket, 3000);
  };
}

function handleWebSocketMessage(packet) {
  const { type, data } = packet;

  if (type === "RAW_LOG") {
    appendTerminalLog(data);
    incrementEventCount();
  } else if (type === "INCIDENT_CREATED") {
    addOrUpdateIncidentCard(data, true);
    if (data.threat_intel) {
      plotAttackerOnMap(
        data.source_ip,
        data.threat_intel.latitude,
        data.threat_intel.longitude,
        data.threat_intel.country,
        data.threat_intel.city,
        data.threat_intel.isp,
        data.threat_score,
        data.title
      );
    }
    refreshMetrics();
    playAlertBeep(850, 0.25);
  } else if (type === "INCIDENT_UPDATED") {
    addOrUpdateIncidentCard(data, false);
    refreshMetrics();
  } else if (type === "INITIAL_METRICS") {
    updateMetricsUI(data);
  }
}

function appendTerminalLog(evt) {
  const terminal = document.getElementById("terminalLogs");
  if (!terminal) return;

  const div = document.createElement("div");
  div.className = `terminal-line ${evt.status || 'INFO'}`;

  const ts = new Date(evt.timestamp || Date.now()).toLocaleTimeString();
  div.innerHTML = `
    <span class="term-ts">[${ts}]</span>
    <span class="term-ip">${evt.source_ip}</span>
    <span class="term-svc">${evt.service || 'sys'}:</span>
    <span class="term-msg">${escapeHtml(evt.message)}</span>
  `;

  terminal.prepend(div);

  while (terminal.children.length > maxTerminalLines) {
    terminal.removeChild(terminal.lastChild);
  }
}

function incrementEventCount() {
  const el = document.getElementById("metricTotalEvents");
  if (el) {
    let current = parseInt(el.innerText.replace(/,/g, "")) || 0;
    el.innerText = (current + 1).toLocaleString();
  }
}

function addOrUpdateIncidentCard(inc, isNew = false) {
  const container = document.getElementById("incidentList");
  if (!container) return;

  let existing = document.getElementById(`inc-card-${inc.id}`);
  if (existing) {
    existing.remove();
  }

  const card = document.createElement("div");
  card.id = `inc-card-${inc.id}`;
  card.className = "incident-card";
  card.onclick = () => openIncidentModal(inc.id);

  const flag = inc.threat_intel ? inc.threat_intel.country_code : "XX";
  const geo = inc.threat_intel ? `${inc.threat_intel.city}, ${inc.threat_intel.country}` : "Unknown Origin";

  card.innerHTML = `
    <div class="inc-header">
      <span class="inc-title">${escapeHtml(inc.title)}</span>
      <span class="sev-badge sev-${inc.severity}">${inc.severity}</span>
    </div>
    <div class="inc-meta">
      <span>🎯 <code>${inc.source_ip}</code> (${geo})</span>
      <span>⚡ ${inc.mitre_technique}</span>
      <span>🛡️ ${inc.status}</span>
    </div>
  `;

  container.prepend(card);
}

async function loadInitialData() {
  try {
    const [metricsRes, incidentsRes, logsRes] = await Promise.all([
      fetch("/api/v1/metrics").then(r => r.json()),
      fetch("/api/v1/incidents?limit=20").then(r => r.json()),
      fetch("/api/v1/logs/recent?limit=40").then(r => r.json())
    ]);

    updateMetricsUI(metricsRes);

    if (incidentsRes.incidents) {
      const container = document.getElementById("incidentList");
      container.innerHTML = "";
      incidentsRes.incidents.reverse().forEach(inc => {
        addOrUpdateIncidentCard(inc);
        if (inc.threat_intel && inc.threat_intel.latitude) {
          plotAttackerOnMap(
            inc.source_ip,
            inc.threat_intel.latitude,
            inc.threat_intel.longitude,
            inc.threat_intel.country,
            inc.threat_intel.city,
            inc.threat_intel.isp,
            inc.threat_score,
            inc.title
          );
        }
      });
    }

    if (logsRes.events) {
      const terminal = document.getElementById("terminalLogs");
      terminal.innerHTML = "";
      logsRes.events.forEach(evt => appendTerminalLog(evt));
    }
  } catch (e) {
    console.error("[AegisSOAR] Error loading initial state", e);
  }
}

async function refreshMetrics() {
  try {
    const metrics = await fetch("/api/v1/metrics").then(r => r.json());
    updateMetricsUI(metrics);
  } catch (e) {
    console.error(e);
  }
}

function updateMetricsUI(metrics) {
  document.getElementById("metricTotalEvents").innerText = (metrics.total_events || 0).toLocaleString();
  document.getElementById("metricActiveIncidents").innerText = (metrics.active_incidents || 0).toLocaleString();
  document.getElementById("metricBlockedIPs").innerText = (metrics.blocked_ips || 0).toLocaleString();
  document.getElementById("metricCritical").innerText = (metrics.critical_incidents || 0).toLocaleString();

  const mitreContainer = document.getElementById("mitreBars");
  if (mitreContainer && metrics.mitre_tactics) {
    mitreContainer.innerHTML = "";
    const maxVal = Math.max(...metrics.mitre_tactics.map(m => m.count), 1);
    metrics.mitre_tactics.forEach(item => {
      const pct = Math.round((item.count / maxVal) * 100);
      const div = document.createElement("div");
      div.className = "mitre-item";
      div.innerHTML = `
        <div class="mitre-header">
          <span>${item.tactic}</span>
          <span style="color: var(--accent-cyan); font-weight: bold;">${item.count}</span>
        </div>
        <div class="mitre-bar-track">
          <div class="mitre-bar-fill" style="width: ${pct}%;"></div>
        </div>
      `;
      mitreContainer.appendChild(div);
    });
  }
}

async function openIncidentModal(incidentId) {
  try {
    const res = await fetch(`/api/v1/incidents/${incidentId}`).then(r => r.json());
    const inc = res.incident;
    const evidence = res.evidence_events || [];

    document.getElementById("modalTitle").innerText = `Case File: ${inc.id} - ${inc.title}`;

    const intel = inc.threat_intel || {};
    const body = document.getElementById("modalBody");
    body.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; background: rgba(255,255,255,0.03); padding: 12px; border-radius: 8px;">
        <div><strong>Attacker IP:</strong> <code>${inc.source_ip}</code></div>
        <div><strong>Threat Score:</strong> <span style="color: #ef4444; font-weight: bold;">${inc.threat_score}/100</span></div>
        <div><strong>Origin:</strong> ${intel.city || 'N/A'}, ${intel.country || 'N/A'}</div>
        <div><strong>Network / ISP:</strong> ${intel.isp || 'N/A'}</div>
        <div><strong>MITRE Technique:</strong> ${inc.mitre_technique} (${inc.mitre_technique_name})</div>
        <div><strong>Current Status:</strong> <span style="color: var(--accent-green); font-weight: bold;">${inc.status}</span></div>
      </div>

      <div>
        <h4 style="margin-bottom: 6px; color: var(--accent-cyan); text-transform: uppercase; font-size: 0.78rem;">Description</h4>
        <p style="color: var(--text-muted); font-size: 0.82rem;">${escapeHtml(inc.description)}</p>
      </div>

      <div>
        <h4 style="margin-bottom: 6px; color: var(--accent-cyan); text-transform: uppercase; font-size: 0.78rem;">Automated Response Playbook History</h4>
        <div style="font-family: var(--font-mono); font-size: 0.75rem; background: #050811; padding: 10px; border-radius: 6px;">
          ${(inc.playbook_executions && inc.playbook_executions.length > 0) ? inc.playbook_executions.map(e => `✓ Executed Playbook Record: ${e}`).join('<br>') : 'No playbooks triggered yet.'}
        </div>
      </div>

      <div>
        <h4 style="margin-bottom: 6px; color: var(--accent-cyan); text-transform: uppercase; font-size: 0.78rem;">Correlated Evidence Events (${evidence.length})</h4>
        <div style="max-height: 140px; overflow-y: auto; font-family: var(--font-mono); font-size: 0.72rem; background: #050811; padding: 8px; border-radius: 6px;">
          ${evidence.map(e => `<div style="padding: 2px 0;">[${new Date(e.timestamp).toLocaleTimeString()}] ${escapeHtml(e.message)}</div>`).join('')}
        </div>
      </div>
    `;

    const footer = document.getElementById("modalFooter");
    footer.innerHTML = `
      <button class="btn btn-danger" onclick="triggerManualPlaybook('${inc.id}', 'PB_CONTAIN_IP_QUARANTINE')">Quarantine IP</button>
      <button class="btn btn-secondary" onclick="updateIncidentStatus('${inc.id}', 'RESOLVED')">Mark Resolved</button>
      <button class="btn btn-secondary" onclick="updateIncidentStatus('${inc.id}', 'FALSE_POSITIVE')">False Positive</button>
      <button class="btn btn-secondary" onclick="closeModal('incidentModal')">Close</button>
    `;

    document.getElementById("incidentModal").classList.add("active");
  } catch (e) {
    console.error(e);
  }
}

async function triggerManualPlaybook(incidentId, playbookId) {
  try {
    await fetch(`/api/v1/incidents/${incidentId}/playbook?playbook_id=${playbookId}`, { method: "POST" });
    closeModal("incidentModal");
    refreshMetrics();
    alert(`Playbook ${playbookId} executed successfully.`);
  } catch (e) {
    alert("Error executing playbook");
  }
}

async function updateIncidentStatus(incidentId, status) {
  try {
    await fetch(`/api/v1/incidents/${incidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: status, note: `Analyst marked case as ${status}` })
    });
    closeModal("incidentModal");
    refreshMetrics();
  } catch (e) {
    alert("Error updating incident");
  }
}

async function launchSimulation(scenario) {
  try {
    const btn = document.getElementById(`sim-${scenario}`);
    if (btn) {
      btn.innerText = "Attacking...";
      btn.disabled = true;
    }

    const res = await fetch("/api/v1/simulator/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenario })
    }).then(r => r.json());

    if (btn) {
      btn.innerText = "Launch";
      btn.disabled = false;
    }

    closeModal("simulatorModal");
  } catch (e) {
    console.error(e);
    alert("Error executing scenario simulation");
  }
}

async function openFirewallModal() {
  try {
    const res = await fetch("/api/v1/firewall/blocklist").then(r => r.json());
    const body = document.getElementById("firewallModalBody");

    if (!res.blocklist || res.blocklist.length === 0) {
      body.innerHTML = "<p style='color: var(--text-muted);'>No IPs are currently quarantined in the firewall.</p>";
    } else {
      body.innerHTML = `
        <div style="font-family: var(--font-mono); font-size: 0.78rem;">
          ${res.blocklist.map(entry => `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: rgba(255,255,255,0.03); margin-bottom: 6px; border-radius: 6px;">
              <div>
                <strong style="color: #ef4444;">${entry.ip}</strong><br>
                <span style="font-size: 0.7rem; color: #94a3b8;">${escapeHtml(entry.reason)}</span>
              </div>
              <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 0.72rem;" onclick="releaseBlockedIp('${entry.ip}')">Unblock</button>
            </div>
          `).join('')}
        </div>
      `;
    }

    document.getElementById("firewallModal").classList.add("active");
  } catch (e) {
    console.error(e);
  }
}

async function releaseBlockedIp(ip) {
  try {
    await fetch(`/api/v1/firewall/blocklist/${ip}`, { method: "DELETE" });
    openFirewallModal();
    refreshMetrics();
  } catch (e) {
    alert("Error unblocking IP");
  }
}

function setupEventListeners() {
  document.getElementById("btnSimulator").onclick = () => {
    document.getElementById("simulatorModal").classList.add("active");
  };

  document.getElementById("btnFirewall").onclick = () => {
    openFirewallModal();
  };

  document.getElementById("btnAudioToggle").onclick = () => {
    audioEnabled = !audioEnabled;
    const btn = document.getElementById("btnAudioToggle");
    btn.innerText = audioEnabled ? "🔊 Sound: ON" : "🔇 Sound: OFF";
    btn.style.color = audioEnabled ? "#10b981" : "#94a3b8";
    if (audioEnabled) playAlertBeep(440, 0.1);
  };
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.remove("active");
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
