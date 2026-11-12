let ws;
let audioEnabled = false;
let audioCtx = null;
const maxTerminalLines = 80;
const maxRememberedEventIds = 1000;
const recentEvents = [];
const renderedEventIds = new Set();
const renderedEventIdOrder = [];
const incidentCache = new Map();
let latestSeverityCounts = null;

document.addEventListener("DOMContentLoaded", () => {
  initThreatMap();
  connectWebSocket();
  loadInitialData();
  loadSessionProfile();
  setupEventListeners();
  if (typeof window.initWorkspaceNavigation === "function") window.initWorkspaceNavigation();
  updateDashboardClock();
  window.setInterval(updateDashboardClock, 1000);
});

async function loadSessionProfile() {
  try {
    const profile = await fetchJSON("/api/v1/auth/me");
    const name = document.getElementById("profileName");
    const context = document.getElementById("profileContext");
    const avatar = document.getElementById("profileAvatar");
    const displayName = profile.full_name || profile.username || "Profile unavailable";
    if (name) name.textContent = displayName;
    if (context) context.textContent = [profile.role, profile.organization_id].filter(Boolean).join(" · ") || "Session context";
    if (avatar) avatar.textContent = displayName.split(/\s+/).slice(0, 2).map(part => part[0]).join("").toUpperCase();
  } catch (error) {
    console.error("[AegisSOAR] Error loading session profile", error);
    const name = document.getElementById("profileName");
    const context = document.getElementById("profileContext");
    if (name) name.textContent = "Session unavailable";
    if (context) context.textContent = "Profile endpoint unavailable";
  }
}

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
    setConnectionStatus("CONNECTED", "#22c98b");
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
    setConnectionStatus("RECONNECTING", "#ff9a3c");
    setTimeout(connectWebSocket, 3000);
  };
}

function setConnectionStatus(label, color) {
  const status = document.getElementById("wsStatus");
  if (status) {
    status.innerText = label;
    status.style.color = color;
  }
}

function handleWebSocketMessage(packet) {
  const { type, data } = packet;

  if (type === "RAW_LOG") {
    if (!appendTerminalLog(data)) return;
    recentEvents.unshift(data);
    recentEvents.length = Math.min(recentEvents.length, 40);
    renderThreatTrend(recentEvents);
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
        data.title,
        data.severity,
        data.id,
        data.threat_intel.source
      );
    }
    refreshMetrics();
    playAlertBeep(850, 0.25);
  } else if (type === "INCIDENT_UPDATED") {
    addOrUpdateIncidentCard(data, false);
    if (["RESOLVED", "FALSE_POSITIVE"].includes(String(data.status).toUpperCase())) {
      removeThreatFromMap(data.id);
    }
    refreshMetrics();
  }
}

function appendTerminalLog(evt) {
  const terminal = document.getElementById("terminalLogs");
  if (!terminal) return false;

  if (evt.id && renderedEventIds.has(String(evt.id))) return false;
  if (evt.id) {
    const eventId = String(evt.id);
    renderedEventIds.add(eventId);
    renderedEventIdOrder.push(eventId);
    if (renderedEventIdOrder.length > maxRememberedEventIds) {
      renderedEventIds.delete(renderedEventIdOrder.shift());
    }
  }
  if (terminal.querySelector(".empty-state")) terminal.innerHTML = "";
  const div = document.createElement("div");
  const status = ["FAILURE", "SUCCESS", "INFO"].includes(String(evt.status || "").toUpperCase())
    ? String(evt.status).toUpperCase()
    : "INFO";
  div.className = `terminal-line ${status}`;
  if (evt.id) div.dataset.eventId = String(evt.id);

  const timestamp = evt.timestamp ? new Date(evt.timestamp) : null;
  const validTimestamp = timestamp && Number.isFinite(timestamp.getTime());
  const ts = validTimestamp
    ? timestamp.toLocaleString([], { hour12: false })
    : "Time unavailable";
  const eventType = escapeHtml(evt.service || evt.event_type || "event");
  div.dataset.eventTimestamp = validTimestamp ? String(timestamp.getTime()) : "0";
  div.innerHTML = `
    <time class="term-ts"${validTimestamp ? ` datetime="${escapeHtml(timestamp.toISOString())}"` : ""}>${escapeHtml(ts)}</time>
    <span class="term-ip">${escapeHtml(evt.source_ip || "—")}</span>
    <span class="term-status">${escapeHtml(status)}</span>
    <span class="term-msg"><span class="term-type">${eventType}</span>${escapeHtml(evt.message || "Event received")}</span>
  `;

  const timestampValue = Number(div.dataset.eventTimestamp);
  const nextNewerEvent = Array.from(terminal.querySelectorAll(".terminal-line"))
    .find(line => Number(line.dataset.eventTimestamp || 0) < timestampValue);
  terminal.insertBefore(div, nextNewerEvent || null);

  while (terminal.children.length > maxTerminalLines) {
    const removed = terminal.lastElementChild;
    terminal.removeChild(terminal.lastChild);
  }
  return true;
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
  if (!container || !inc || !inc.id) return;

  incidentCache.set(String(inc.id), inc);
  const existing = Array.from(container.querySelectorAll(".incident-card"))
    .find(card => card.dataset.incidentId === String(inc.id));
  if (existing) existing.remove();
  if (container.querySelector(".empty-state")) container.innerHTML = "";

  const card = document.createElement("div");
  card.className = "incident-card";
  card.dataset.incidentId = String(inc.id);
  card.addEventListener("click", () => openIncidentModal(inc.id));

  const geo = inc.threat_intel
    ? [inc.threat_intel.city, inc.threat_intel.country].filter(Boolean).join(", ")
    : "Unknown origin";
  const severity = String(inc.severity || "UNKNOWN").toUpperCase();

  card.innerHTML = `
    <div class="inc-header">
      <span class="inc-title">${escapeHtml(inc.title || "Untitled incident")}<small>${escapeHtml(inc.id)}</small></span>
      <span class="sev-badge sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span>
    </div>
    <div class="inc-meta">
      <span><code>${escapeHtml(inc.source_ip || "—")}</code> · ${escapeHtml(geo)}</span>
      <span>${escapeHtml(inc.mitre_technique || "No technique mapped")}</span>
      <span>${escapeHtml(inc.status || "UNKNOWN")}</span>
    </div>
  `;

  container.prepend(card);
  updateSeverityDistribution();
  if (isNew && inc.threat_intel) {
    plotAttackerOnMap(
      inc.source_ip,
      inc.threat_intel.latitude,
      inc.threat_intel.longitude,
      inc.threat_intel.country,
      inc.threat_intel.city,
      inc.threat_intel.isp,
      inc.threat_score,
      inc.title,
      inc.severity,
      inc.id,
      inc.threat_intel.source
    );
  }
}

async function loadInitialData() {
  const results = await Promise.allSettled([
    fetchJSON("/api/v1/metrics"),
    fetchJSON("/api/v1/incidents?limit=20"),
    fetchJSON("/api/v1/logs/recent?limit=40")
  ]);

  if (results[0].status === "fulfilled") {
    updateMetricsUI(results[0].value);
  } else {
    console.error("[AegisSOAR] Error loading dashboard metrics", results[0].reason);
    const metricsStatus = document.getElementById("metricsStatus");
    const metricsStatusText = document.getElementById("metricsStatusText");
    if (metricsStatus && metricsStatusText) {
      metricsStatusText.innerText = "UNAVAILABLE";
      metricsStatus.classList.add("metrics-unavailable");
    }
  }

  if (results[1].status === "fulfilled") {
    const container = document.getElementById("incidentList");
    container.innerHTML = "";
    incidentCache.clear();
    const incidents = results[1].value.incidents || [];
    incidents.slice().reverse().forEach(inc => {
      addOrUpdateIncidentCard(inc);
      if (inc.threat_intel) {
        plotAttackerOnMap(
          inc.source_ip,
          inc.threat_intel.latitude,
          inc.threat_intel.longitude,
          inc.threat_intel.country,
          inc.threat_intel.city,
          inc.threat_intel.isp,
          inc.threat_score,
          inc.title,
          inc.severity,
          inc.id,
          inc.threat_intel.source
        );
      }
    });
    fitThreatMapToMarkers();
    if (!incidents.length) container.innerHTML = '<div class="empty-state">No incidents were returned by the backend.</div>';
  } else {
    console.error("[AegisSOAR] Error loading incidents", results[1].reason);
    document.getElementById("incidentList").innerHTML = '<div class="empty-state">Incident data is unavailable. Check the backend connection.</div>';
  }

  if (results[2].status === "fulfilled") {
    const events = results[2].value.events || [];
    recentEvents.splice(0, recentEvents.length, ...events.slice(-40).reverse());
    const terminal = document.getElementById("terminalLogs");
    recentEvents.forEach(appendTerminalLog);
    if (!events.length && !terminal.querySelector(".terminal-line")) {
      terminal.innerHTML = '<div class="empty-state">No recent events were returned by the backend.</div>';
    }
    renderThreatTrend(recentEvents);
  } else {
    console.error("[AegisSOAR] Error loading recent events", results[2].reason);
    const terminal = document.getElementById("terminalLogs");
    if (!terminal.querySelector(".terminal-line")) {
      terminal.innerHTML = '<div class="empty-state">Event data is unavailable. Check the backend connection.</div>';
    }
  }
}

async function refreshMetrics() {
  try {
    const metrics = await fetchJSON("/api/v1/metrics");
    updateMetricsUI(metrics);
  } catch (e) {
    console.error("[AegisSOAR] Error refreshing dashboard metrics", e);
  }
}

function updateMetricsUI(metrics) {
  const metricsStatus = document.getElementById("metricsStatus");
  const metricsStatusText = document.getElementById("metricsStatusText");
  if (metricsStatus && metricsStatusText) {
    metricsStatusText.innerText = "LIVE";
    metricsStatus.classList.remove("metrics-loading", "metrics-unavailable");
  }
  setMetric("metricTotalEvents", metrics.total_events);
  setMetric("metricActiveIncidents", metrics.active_incidents);
  setMetric("metricBlockedIPs", metrics.blocked_ips);
  setMetric("metricCritical", metrics.critical_incidents);
  const notificationCount = document.getElementById("notificationCount");
  if (notificationCount) notificationCount.innerText = formatMetric(metrics.active_incidents);
  if (metrics.severity_counts) latestSeverityCounts = metrics.severity_counts;
  updateSeverityDistribution();

  const mitreContainer = document.getElementById("mitreBars");
  if (mitreContainer) {
    mitreContainer.innerHTML = "";
    const tactics = Array.isArray(metrics.mitre_tactics) ? metrics.mitre_tactics : [];
    const maxVal = Math.max(...tactics.map(m => Number(m.count) || 0), 1);
    tactics.forEach(item => {
      const pct = Math.round((item.count / maxVal) * 100);
      const div = document.createElement("div");
      div.className = "mitre-item";
      div.innerHTML = `
        <div class="mitre-header">
          <span>${escapeHtml(item.tactic || "Unspecified tactic")}</span>
          <span>${formatMetric(item.count)}</span>
        </div>
        <div class="mitre-bar-track">
          <div class="mitre-bar-fill" style="width: ${pct}%;"></div>
        </div>
      `;
      mitreContainer.appendChild(div);
    });
    if (!tactics.length) mitreContainer.innerHTML = '<div class="empty-state">No MITRE tactic correlations are available.</div>';
  }
}

function formatMetric(value) {
  if (value === null || value === undefined || value === "") return "—";
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed.toLocaleString() : "—";
}

function setMetric(id, value) {
  const element = document.getElementById(id);
  if (element) element.innerText = formatMetric(value);
}

async function fetchJSON(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`${url} returned HTTP ${response.status}`);
  }
  return response.json();
}

function updateSeverityDistribution(backendCounts = latestSeverityCounts) {
  const chart = document.getElementById("severityChart");
  const legend = document.getElementById("severityLegend");
  const totalElement = document.getElementById("severityTotal");
  if (!chart || !legend || !totalElement) return;

  const severities = [
    { key: "CRITICAL", className: "severity-critical", color: "#ff465b" },
    { key: "HIGH", className: "severity-high", color: "#ff9a3c" },
    { key: "MEDIUM", className: "severity-medium", color: "#f5ca52" },
    { key: "LOW", className: "severity-low", color: "#22c98b" },
    { key: "OTHER", className: "severity-other", color: "#8296ad" }
  ];
  const counts = Object.fromEntries(severities.map(({ key }) => [
    key,
    Number.isFinite(Number(backendCounts && backendCounts[key]))
      ? Number(backendCounts[key])
      : Array.from(incidentCache.values()).filter(incident =>
        !["RESOLVED", "FALSE_POSITIVE"].includes(String(incident.status || "").toUpperCase()) &&
        (key === "OTHER"
          ? !["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(String(incident.severity || "").toUpperCase())
          : String(incident.severity || "").toUpperCase() === key)
      ).length
  ]));
  const total = severities.reduce((sum, { key }) => sum + counts[key], 0);
  totalElement.innerText = formatMetric(total);

  if (!total) {
    chart.style.background = "conic-gradient(#304454 0deg 360deg)";
  } else {
    let start = 0;
    const segments = severities.map(({ key, color }) => {
      const end = start + counts[key] / total * 360;
      const segment = `${color} ${start}deg ${end}deg`;
      start = end;
      return segment;
    });
    chart.style.background = `conic-gradient(${segments.join(", ")})`;
  }

  legend.innerHTML = severities.map(({ key, className }) => `
    <div class="severity-row ${className}">
      <i class="severity-dot"></i><span>${key}</span><strong>${counts[key]}</strong>
    </div>
  `).join("");
  if (!total) legend.innerHTML = '<div class="empty-state">No active incidents in the loaded set.</div>';
}

function renderThreatTrend(events) {
  const chart = document.getElementById("threatTrend");
  const caption = document.getElementById("trendCaption");
  if (!chart) return;

  const timestamps = events
    .map(event => Date.parse(event.timestamp))
    .filter(timestamp => Number.isFinite(timestamp));
  if (!timestamps.length) {
    chart.innerHTML = '<span class="empty-state">No timestamped event data available.</span>';
    return;
  }

  const minTime = Math.min(...timestamps);
  const maxTime = Math.max(...timestamps);
  const bucketCount = minTime === maxTime ? 1 : 8;
  const span = Math.max(maxTime - minTime, 1);
  const buckets = new Array(bucketCount).fill(0);
  timestamps.forEach(timestamp => {
    const index = Math.min(bucketCount - 1, Math.floor(((timestamp - minTime) / span) * bucketCount));
    buckets[index] += 1;
  });
  const maxCount = Math.max(...buckets, 1);
  chart.innerHTML = buckets.map((count, index) => {
    const height = Math.max(count ? 8 : 3, Math.round((count / maxCount) * 100));
    return `<span class="trend-bar" style="height:${height}%" title="${count} event${count === 1 ? "" : "s"} in time bucket ${index + 1}"></span>`;
  }).join("");
  if (caption) caption.innerText = `${timestamps.length} timestamped events`;
  chart.setAttribute("aria-label", `Recent event volume across ${bucketCount} time buckets`);
}

function updateDashboardClock() {
  const clock = document.getElementById("dashboardClock");
  if (clock) {
    clock.innerText = new Intl.DateTimeFormat("en-GB", {
      timeZone: "UTC",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }).format(new Date());
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

async function openAiModal() {
  try {
    const res = await fetchJSON("/api/v1/ai/insights");
    const content = document.getElementById("aiInsightsContent");
    const fallbackMode = /fallback|offline/i.test(String(res.soar_health || ""));
    const threatVectors = Array.isArray(res.top_threat_vectors) ? res.top_threat_vectors : [];
    content.innerHTML = `
      <div class="workspace-notice warning"><strong>AI analysis is advisory</strong><p>The existing AI endpoint does not filter telemetry by organization. Do not treat generated summaries or fallback vectors as confirmed, tenant-specific detections.</p></div>
      <div style="color: var(--accent-cyan); margin-bottom: 10px;">SYSTEM INSIGHTS</div>
      <div>${escapeHtml(res.insights_summary || "No analysis summary was returned.")}</div>
      <div style="margin-top: 10px; color: var(--accent-cyan);">THREAT VECTORS</div>
      ${fallbackMode
        ? '<div class="workspace-empty">The backend reports fallback or offline mode; threat vectors are not event-confirmed.</div>'
        : threatVectors.map(vector => `<div>– ${escapeHtml(vector)}</div>`).join("") || '<div class="workspace-empty">No threat vectors were returned.</div>'}
      <div style="margin-top: 10px; color: var(--accent-cyan);">SOAR STATUS</div>
      <div>Health: ${escapeHtml(res.soar_health || "Not reported")}</div>
      <div>Recommended playbook: ${escapeHtml(res.recommended_playbook || "None reported")}</div>
    `;
    document.getElementById("aiModal").classList.add("active");
  } catch (error) {
    console.error("[AegisSOAR] Error loading AI insights", error);
    const content = document.getElementById("aiInsightsContent");
    content.innerHTML = `<div class="workspace-error" role="status"><strong>AI insights unavailable</strong><p>${escapeHtml(error.message)}</p></div>`;
    document.getElementById("aiModal").classList.add("active");
  }
}

async function openEndpointsModal() {
  const body = document.getElementById("endpointsModalBody");
  try {
    await fetchJSON("/api/v1/endpoints");
    body.innerHTML = `
      <div class="workspace-notice warning"><strong>Unverified endpoint source</strong><p>The endpoint API currently returns a process-local simulated list, not a trusted organization-scoped inventory. Its records and counts are not shown as live endpoint telemetry.</p></div>
    `;
    document.getElementById("endpointsModal").classList.add("active");
  } catch (error) {
    console.error("[AegisSOAR] Error loading endpoint inventory", error);
    body.innerHTML = `<div class="workspace-error" role="status"><strong>Endpoint API unavailable</strong><p>${escapeHtml(error.message)}</p></div>`;
    document.getElementById("endpointsModal").classList.add("active");
  }
}

async function openReportsModal() {
  document.getElementById("reportContentArea").style.display = "none";
  document.getElementById("reportsModal").classList.add("active");
}

async function loadExecutiveReport() {
  try {
    const results = await Promise.allSettled([
      fetchJSON("/api/v1/metrics"),
      fetchJSON("/api/v1/incidents?limit=200"),
      fetchJSON("/api/v1/logs/recent?limit=500")
    ]);
    const metrics = results[0].status === "fulfilled" ? results[0].value : {};
    const incidentCount = results[1].status === "fulfilled" ? (results[1].value.incidents || []).length : null;
    const eventCount = results[2].status === "fulfilled" ? (results[2].value.events || []).length : null;
    const area = document.getElementById("reportContentArea");
    area.innerHTML = `
      <div style="color: var(--accent-cyan); font-weight: bold; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-bottom: 10px;">
        Organization-scoped security summary
      </div>
      <div style="line-height: 1.6;">
        TOTAL EVENTS: ${formatMetric(metrics.total_events)}<br>
        ACTIVE INCIDENTS: ${formatMetric(metrics.active_incidents)}<br>
        CRITICAL INCIDENTS: ${formatMetric(metrics.critical_incidents)}<br>
        LATEST EVENTS LOADED: ${formatMetric(eventCount)}<br>
        LATEST INCIDENTS LOADED: ${formatMetric(incidentCount)}<br>
        GENERATED: ${escapeHtml(new Date().toISOString())}
      </div>
      ${results.some(result => result.status === "rejected") ? '<p class="workspace-empty">Some scoped report sources were unavailable; see the page for a source-level status.</p>' : ""}
    `;
    area.style.display = "block";
  } catch (error) {
    console.error("[AegisSOAR] Error loading scoped report", error);
    const area = document.getElementById("reportContentArea");
    area.innerHTML = `<div class="workspace-error" role="status"><strong>Report unavailable</strong><p>${escapeHtml(error.message)}</p></div>`;
    area.style.display = "block";
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

  const mapFilter = document.getElementById("mapThreatFilter");
  if (mapFilter) mapFilter.addEventListener("change", () => filterThreatMap(mapFilter.value));

  const complianceReport = document.getElementById("openComplianceReport");
  if (complianceReport) complianceReport.addEventListener("click", openReportsModal);

  const notifications = document.querySelector(".notification-indicator");
  if (notifications) notifications.addEventListener("click", () => {
    if (typeof window.navigateWorkspace === "function") window.navigateWorkspace("incidents");
  });
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.remove("active");
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
