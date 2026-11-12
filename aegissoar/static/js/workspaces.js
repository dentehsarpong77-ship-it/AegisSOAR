const WORKSPACE_PAGES = {
  threats: {
    title: "Threat monitoring",
    description: "Investigate organization-scoped security events and incident severity.",
    eyebrow: "DETECTION / EVENT REVIEW"
  },
  endpoints: {
    title: "Endpoint security",
    description: "Endpoint protection metrics are unavailable until a trusted fleet inventory is connected.",
    eyebrow: "ASSET SECURITY"
  },
  cloud: {
    title: "Cloud security",
    description: "Cloud posture and asset visibility require a connected cloud-provider integration.",
    eyebrow: "CLOUD POSTURE"
  },
  network: {
    title: "Network security",
    description: "Review network-related security events currently available to this organization.",
    eyebrow: "NETWORK OPERATIONS"
  },
  intelligence: {
    title: "Threat intelligence",
    description: "Look up an IP address using the existing intelligence service and inspect the source quality.",
    eyebrow: "INDICATOR INVESTIGATION"
  },
  ai: {
    title: "AI Analyst",
    description: "Use the existing AI workflow only with clear awareness of its current data scope and evidence limits.",
    eyebrow: "ASSISTED INVESTIGATION"
  },
  incidents: {
    title: "Incident management",
    description: "Triage organization-scoped incidents and open existing response workflows.",
    eyebrow: "INCIDENT RESPONSE"
  },
  reports: {
    title: "Security reports",
    description: "Review and export the latest organization-scoped events and incidents available from the API.",
    eyebrow: "REPORTING"
  },
  settings: {
    title: "Settings",
    description: "Review the authenticated session and organization context available to this application.",
    eyebrow: "ACCOUNT / ORGANIZATION"
  }
};

let activeWorkspace = "dashboard";
let workspaceRenderSequence = 0;
let reportSnapshot = null;

function initWorkspaceNavigation() {
  document.querySelector(".primary-nav").addEventListener("click", event => {
    const link = event.target.closest("a[href^='#']");
    if (!link) return;
    event.preventDefault();
    navigateWorkspace(link.getAttribute("href").slice(1));
  });

  window.addEventListener("hashchange", () => {
    const route = window.location.hash.slice(1) || "dashboard";
    showWorkspace(route);
  });

  const workspaceView = document.getElementById("workspaceView");
  workspaceView.addEventListener("click", event => {
    const refresh = event.target.closest("[data-workspace-refresh]");
    if (refresh) showWorkspace(activeWorkspace);

    const incidentButton = event.target.closest("[data-open-incident]");
    if (incidentButton && typeof window.openIncidentModal === "function") {
      window.openIncidentModal(incidentButton.dataset.openIncident);
    }

  });

  workspaceView.addEventListener("input", event => {
    if (event.target.matches("[data-event-search]")) filterEventTable();
  });
  workspaceView.addEventListener("change", event => {
    if (event.target.matches("[data-event-severity]")) filterEventTable();
    if (event.target.matches("[data-incident-filter]")) filterIncidentTable();
    if (event.target.matches("[data-report-range]")) updateReportRange();
  });
  workspaceView.addEventListener("submit", event => {
    if (event.target.matches("#intelLookupForm")) {
      event.preventDefault();
      lookupWorkspaceIp();
    }
  });

  showWorkspace(window.location.hash.slice(1) || "dashboard");
}

function navigateWorkspace(route) {
  const next = route === "dashboard" || WORKSPACE_PAGES[route] ? route : "dashboard";
  if (window.location.hash === `#${next}` || (!window.location.hash && next === "dashboard")) {
    showWorkspace(next);
  } else {
    window.location.hash = next;
  }
}

function showWorkspace(route) {
  const nextRoute = route === "dashboard" || WORKSPACE_PAGES[route] ? route : "dashboard";
  activeWorkspace = nextRoute;
  const dashboard = document.getElementById("dashboard");
  const workspaceView = document.getElementById("workspaceView");
  dashboard.hidden = nextRoute !== "dashboard";
  workspaceView.hidden = nextRoute === "dashboard";

  document.querySelectorAll(".primary-nav .nav-link").forEach(link => {
    const isActive = link.getAttribute("href") === `#${nextRoute}`;
    link.classList.toggle("active", isActive);
    if (isActive) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });

  const sequence = ++workspaceRenderSequence;
  if (nextRoute === "dashboard") {
    workspaceView.replaceChildren();
    if (typeof window.resizeThreatMap === "function") window.resizeThreatMap();
    return;
  }

  const page = WORKSPACE_PAGES[nextRoute];
  workspaceView.innerHTML = workspaceShell(
    page,
    '<section class="workspace-card"><div class="workspace-loading" role="status">Loading organization data…</div></section>'
  );
  const renderers = {
    threats: renderThreatWorkspace,
    endpoints: renderEndpointWorkspace,
    cloud: renderCloudWorkspace,
    network: renderNetworkWorkspace,
    intelligence: renderIntelligenceWorkspace,
    ai: renderAiWorkspace,
    incidents: renderIncidentWorkspace,
    reports: renderReportWorkspace,
    settings: renderSettingsWorkspace
  };
  Promise.resolve(renderers[nextRoute]()).then(content => {
    if (sequence === workspaceRenderSequence && activeWorkspace === nextRoute) {
      workspaceView.innerHTML = workspaceShell(page, content);
      if (nextRoute === "threats") filterEventTable();
      if (nextRoute === "network") filterEventTable();
      if (nextRoute === "incidents") filterIncidentTable();
      if (nextRoute === "reports") updateReportRange();
    }
  }).catch(error => {
    console.error(`[AegisSOAR] Failed to load ${nextRoute} workspace`, error);
    if (sequence === workspaceRenderSequence) {
      workspaceView.innerHTML = workspaceShell(
        page,
        `<section class="workspace-card workspace-error"><h2>Workspace unavailable</h2><p>${escapeHtml(error.message || "The requested data could not be loaded.")}</p></section>`
      );
    }
  });
}

function workspaceShell(page, content) {
  return `
    <section class="workspace-page">
      <header class="workspace-page-header">
        <div>
          <div class="workspace-eyebrow">AEGIS / SOC / ${escapeHtml(page.eyebrow)}</div>
          <h1>${escapeHtml(page.title)}</h1>
          <p>${escapeHtml(page.description)}</p>
        </div>
        <button class="btn btn-secondary" type="button" data-workspace-refresh>Refresh</button>
      </header>
      <div class="workspace-content">${content}</div>
    </section>
  `;
}

function workspaceCard(title, subtitle, content, className = "") {
  return `
    <section class="workspace-card ${className}">
      <div class="workspace-card-heading">
        <div><h2>${escapeHtml(title)}</h2>${subtitle ? `<p>${escapeHtml(subtitle)}</p>` : ""}</div>
      </div>
      <div class="workspace-card-body">${content}</div>
    </section>
  `;
}

function workspaceNotice(title, message, kind = "info") {
  return `<div class="workspace-notice ${kind}"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(message)}</p></div>`;
}

function workspaceError(label, error) {
  console.error(`[AegisSOAR] ${label} request failed`, error);
  return `<div class="workspace-error" role="status"><strong>${escapeHtml(label)} unavailable</strong><p>${escapeHtml(error.message || "The backend request failed.")}</p></div>`;
}

function metricCard(label, value, note = "") {
  const isNumericValue = typeof value === "number" || (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value)));
  const displayValue = value === null || value === undefined || value === ""
    ? "—"
    : isNumericValue ? formatMetric(value) : String(value);
  return `<article class="workspace-metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(displayValue)}</strong>${note ? `<small>${escapeHtml(note)}</small>` : ""}</article>`;
}

function eventValue(event, ...keys) {
  for (const key of keys) {
    const value = event && event[key];
    if (value !== null && value !== undefined && String(value).trim()) return value;
  }
  return "";
}

function eventSeverity(event) {
  const severity = String(eventValue(event, "severity", "threat_severity") || "").toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity) ? severity : "UNCLASSIFIED";
}

function eventIdentifier(event) {
  return eventValue(event, "id", "event_id") || "ID unavailable";
}

function formatWorkspaceDate(value) {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function severityBadge(value) {
  const severity = String(value || "UNCLASSIFIED").toUpperCase();
  const safeSeverity = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OTHER"].includes(severity) ? severity : "UNCLASSIFIED";
  return `<span class="workspace-severity sev-${safeSeverity}">${escapeHtml(severity)}</span>`;
}

function verdictBadge(value) {
  const verdict = String(value || "UNCLASSIFIED").toUpperCase();
  const className = {
    MALICIOUS: "MALICIOUS",
    SUSPICIOUS: "SUSPICIOUS",
    CLEAN: "CLEAN"
  }[verdict] || "UNCLASSIFIED";
  return `<span class="workspace-severity sev-${className}">${escapeHtml(verdict)}</span>`;
}

function renderSeverityDistribution(counts = {}) {
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OTHER"];
  const values = severities.map(severity => [severity, Math.max(0, Number(counts[severity]) || 0)]);
  const total = values.reduce((sum, [, count]) => sum + count, 0);
  return `<div class="workspace-severity-list">${values.map(([severity, count]) => {
    const width = total ? Math.round((count / total) * 100) : 0;
    return `<div class="workspace-severity-row"><div>${severityBadge(severity)}<strong>${count.toLocaleString()}</strong></div><div class="workspace-bar"><i class="sev-fill-${severity.toLowerCase()}" style="width:${width}%"></i></div></div>`;
  }).join("")}${total === 0 ? '<p class="workspace-empty">No active incidents are reported.</p>' : ""}</div>`;
}

async function loadEvents(limit = 500) {
  return fetchJSON(`/api/v1/logs/recent?limit=${limit}`);
}

async function loadIncidents(limit = 200) {
  return fetchJSON(`/api/v1/incidents?limit=${limit}`);
}

async function renderThreatWorkspace() {
  const results = await Promise.allSettled([
    fetchJSON("/api/v1/metrics"),
    loadIncidents(200),
    loadEvents(500)
  ]);
  const metrics = results[0].status === "fulfilled" ? results[0].value : null;
  const incidents = results[1].status === "fulfilled" ? (results[1].value.incidents || []) : [];
  const events = results[2].status === "fulfilled" ? (results[2].value.events || []) : [];
  const activeCount = metrics ? metrics.active_incidents : incidents.filter(isActiveIncident).length;
  const content = `
    ${results.some(result => result.status === "rejected") ? workspaceNotice("Partial data", "One or more organization-scoped threat data requests failed. Available sections are shown with their source status.", "warning") : ""}
    ${workspaceCard("Threat overview", "Metrics from the authenticated organization context", `
      <div class="workspace-metrics">
        ${metricCard("Total events", metrics && metrics.total_events, "Backend event records")}
        ${metricCard("Active incidents", activeCount, "Not resolved or false positive")}
        ${metricCard("Critical incidents", metrics && metrics.critical_incidents, "Backend active severity count")}
        ${metricCard("Blocked IPs", metrics && metrics.blocked_ips, "Backend dashboard metric")}
      </div>
      ${metrics ? renderSeverityDistribution(metrics.severity_counts || {}) : workspaceError("Threat metrics", results[0].reason)}
    `)}
    ${workspaceCard("Security event stream", "Latest organization-scoped records; distinct event IDs are preserved", `
      ${results[2].status === "rejected" ? workspaceError("Security events", results[2].reason) : eventTable(events)}
    `)}
  `;
  return content;
}

function eventTable(events, networkMode = false) {
  const rows = events.map(event => {
    const severity = eventSeverity(event);
    const eventType = eventValue(event, "service", "event_type", "type") || "Event";
    const message = eventValue(event, "message", "description") || "No description provided";
    const source = eventValue(event, "source_ip", "src_ip") || "—";
    const destination = eventValue(event, "destination_ip", "dest_ip", "target_ip") || "—";
    const mitre = eventValue(event, "mitre_technique", "technique_id") || "—";
    return `<tr data-event-row data-severity="${escapeHtml(severity)}" data-search="${escapeHtml([eventIdentifier(event), eventType, message, source, destination, mitre].join(" ").toLowerCase())}">
      <td class="mono">${escapeHtml(eventIdentifier(event))}</td>
      <td>${escapeHtml(formatWorkspaceDate(eventValue(event, "timestamp", "created_at")))}</td>
      <td>${severityBadge(severity)}</td>
      <td><strong>${escapeHtml(eventType)}</strong><span class="workspace-cell-subtext">${escapeHtml(message)}</span></td>
      <td class="mono">${escapeHtml(source)}</td>
      <td class="mono">${escapeHtml(destination)}</td>
      <td>${networkMode ? "Event telemetry" : escapeHtml(mitre)}</td>
    </tr>`;
  }).join("");
  return `
    <div class="workspace-table-tools">
      <label class="workspace-search">Search events<input type="search" data-event-search placeholder="ID, type, IP, text…"></label>
      <label class="workspace-select">Severity<select data-event-severity><option value="ALL">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNCLASSIFIED</option></select></label>
      <span class="workspace-record-count" data-event-count>${events.length.toLocaleString()} loaded</span>
    </div>
    <div class="workspace-table-wrap"><table class="workspace-table">
      <thead><tr><th>Event ID</th><th>Timestamp</th><th>Severity</th><th>Event / Description</th><th>Source</th><th>Destination</th><th>${networkMode ? "Feed" : "MITRE ATT&amp;CK"}</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="7" class="workspace-empty">${networkMode ? "No network-related events were returned for this organization." : "No events were returned for this organization."}</td></tr>`}</tbody>
    </table></div>
  `;
}

function filterEventTable() {
  const root = document.getElementById("workspaceView");
  if (!root || !["threats", "network"].includes(activeWorkspace)) return;
  const search = (root.querySelector("[data-event-search]")?.value || "").trim().toLowerCase();
  const severity = root.querySelector("[data-event-severity]")?.value || "ALL";
  let visible = 0;
  root.querySelectorAll("[data-event-row]").forEach(row => {
    const matches = (!search || row.dataset.search.includes(search)) &&
      (severity === "ALL" || row.dataset.severity === severity);
    row.hidden = !matches;
    row.style.display = matches ? "" : "none";
    if (matches) visible += 1;
  });
  const count = root.querySelector("[data-event-count]");
  if (count) count.textContent = `${visible.toLocaleString()} shown`;
}

async function renderEndpointWorkspace() {
  return `
    ${workspaceNotice("Unverified endpoint source", "The current endpoints API returns a process-local simulated inventory with hard-coded records. It is not a trusted, tenant-scoped endpoint fleet, so those entries and their protection metrics are intentionally not presented as live assets.", "warning")}
    ${workspaceCard("Endpoint inventory", "No verified endpoint agent or organization-owned inventory feed is connected", `
      <div class="workspace-empty-state"><span class="workspace-empty-icon" aria-hidden="true">⌘</span><div><h3>No verified endpoint telemetry</h3><p>Connect an authenticated endpoint inventory before reporting device health, protection status, operating systems, or risk.</p></div></div>
      <a class="btn btn-secondary" href="/docs" target="_blank" rel="noopener noreferrer">Review API documentation</a>
    `)}
  `;
}

async function renderCloudWorkspace() {
  return `
    ${workspaceNotice("Integration unavailable", "No cloud-provider inventory or posture API is connected. No cloud assets, findings, or protection claims are inferred.", "warning")}
    ${workspaceCard("Cloud security posture", "Cloud integration status", `
      <div class="workspace-empty-state"><span class="workspace-empty-icon" aria-hidden="true">☁</span><div><h3>No cloud provider connected</h3><p>Cloud asset inventory, configuration findings, and activity are unavailable in the current backend.</p></div></div>
    `)}
  `;
}

async function renderNetworkWorkspace() {
  const result = await Promise.allSettled([loadEvents(500)]);
  if (result[0].status === "rejected") {
    return workspaceCard("Network event telemetry", "Organization-scoped security events", workspaceError("Network events", result[0].reason));
  }
  const events = result[0].value.events || [];
  const networkEvents = events.filter(event =>
    eventValue(event, "source_ip", "src_ip", "destination_ip", "dest_ip", "target_ip") ||
    /network|firewall|connection|dns|http|ssh|tcp|udp/i.test(String(eventValue(event, "service", "event_type", "type") || ""))
  );
  return `
    ${workspaceNotice("Coverage note", "This view uses security events with network-related fields or event types. There is no dedicated network-flow or organization-scoped firewall inventory feed.", "info")}
    ${workspaceCard("Network event telemetry", "Latest organization-scoped events matching available network fields", eventTable(networkEvents, true))}
  `;
}

async function renderIntelligenceWorkspace() {
  return `
    ${workspaceCard("IP reputation lookup", "Existing IP-only threat-intelligence endpoint", `
      <form id="intelLookupForm" class="workspace-lookup-form">
        <label for="intelIpInput">IP address</label>
        <div><input id="intelIpInput" name="ip" type="text" autocomplete="off" placeholder="203.0.113.10" required><button class="btn btn-primary" type="submit">Investigate IP</button></div>
      </form>
      <div id="intelLookupResult" class="workspace-result" aria-live="polite">
        <p class="workspace-empty">Enter an IP address to request a lookup. Domain, file-hash, actor, and feed APIs are not connected.</p>
      </div>
    `)}
    ${workspaceNotice("Source quality", "Live AbuseIPDB responses are labeled with their provider. Bundled reference records and local heuristic fallback results are not independent, externally verified intelligence; fallback geolocation is not shown as accurate.", "warning")}
  `;
}

async function lookupWorkspaceIp() {
  const input = document.getElementById("intelIpInput");
  const result = document.getElementById("intelLookupResult");
  if (!input || !result) return;
  const ip = input.value.trim();
  result.innerHTML = '<p class="workspace-loading" role="status">Requesting intelligence lookup…</p>';
  try {
    const intel = await fetchJSON(`/api/v1/threat-intel/${encodeURIComponent(ip)}`);
    const source = String(intel.source || "");
    const isLive = source === "AbuseIPDB Live API";
    const isBundled = source === "Aegis Threat Intelligence Engine";
    const trustLabel = isLive ? "Live provider response" : isBundled ? "Bundled local reference" : "Local heuristic fallback";
    const threatTypes = Array.isArray(intel.threat_types) ? intel.threat_types : [];
    result.innerHTML = `
      <div class="workspace-intel-result">
        <div class="workspace-intel-heading"><div><span class="workspace-overline">${escapeHtml(trustLabel)}</span><h3>${escapeHtml(intel.ip || ip)}</h3></div>${verdictBadge(intel.verdict)}</div>
        ${workspaceNotice(isLive ? "Provider attribution" : "Not externally verified", `${source || "No provider source was returned."}${isLive ? "" : ". Treat the score and classification as non-authoritative; verify through a trusted source before response."}`, isLive ? "info" : "warning")}
        <div class="workspace-metrics">
          ${metricCard("Reputation score", Number.isFinite(Number(intel.reputation_score)) ? `${intel.reputation_score}/100` : "Unavailable", isLive ? "AbuseIPDB" : trustLabel)}
          ${metricCard("Country", isLive || isBundled ? intel.country : "Not shown", "Geolocation quality varies")}
          ${metricCard("Network", isLive || isBundled ? intel.isp : "Not shown", "Provider-reported")}
        </div>
        <div class="workspace-tag-list">${threatTypes.length ? threatTypes.map(item => `<span>${escapeHtml(item)}</span>`).join("") : '<span>No threat categories returned</span>'}</div>
      </div>
    `;
  } catch (error) {
    result.innerHTML = workspaceError("IP intelligence", error);
  }
}

async function renderAiWorkspace() {
  return `
    ${workspaceNotice("Data-scope limitation", "The existing AI endpoints currently analyze global telemetry without an organization filter. This workspace does not invoke them to avoid presenting cross-organization content. The existing header action remains available for compatibility; do not treat AI summaries as confirmed detections.", "warning")}
    ${workspaceCard("AI-assisted investigation", "Existing backend workflow; not a background detector", `
      <div class="workspace-empty-state"><span class="workspace-empty-icon" aria-hidden="true">◎</span><div><h3>On-demand analysis only</h3><p>Investigation history, event citations, and tenant-scoped analysis are not available through the current AI API.</p></div></div>
      <p class="workspace-empty">The existing AI shortcut remains in the global header. Its current backend response is not organization-scoped.</p>
    `)}
    ${workspaceCard("Evidence and recommendations", "How to interpret generated content", `
      <ul class="workspace-guidance">
        <li>AI output is advisory and must be checked against the underlying event or incident record.</li>
        <li>Recommendations are not automated response actions; use the incident playbook controls for supported actions.</li>
        <li>Fallback-mode output may include generic examples rather than findings from your organization.</li>
      </ul>
    `)}
  `;
}

function isActiveIncident(incident) {
  return !["RESOLVED", "FALSE_POSITIVE"].includes(String(incident.status || "").toUpperCase());
}

async function renderIncidentWorkspace() {
  const result = await Promise.allSettled([loadIncidents(200)]);
  if (result[0].status === "rejected") {
    return workspaceCard("Incident queue", "Organization-scoped incident records", workspaceError("Incident queue", result[0].reason));
  }
  const incidents = result[0].value.incidents || [];
  const sorted = incidents.slice().sort((left, right) =>
    Date.parse(right.updated_at || right.created_at || right.timestamp || "") -
    Date.parse(left.updated_at || left.created_at || left.timestamp || "")
  );
  const rows = sorted.map(incident => {
    const severity = String(incident.severity || "UNCLASSIFIED").toUpperCase();
    const status = String(incident.status || "UNKNOWN").toUpperCase();
    const id = String(incident.id || "");
    return `<tr data-incident-row data-status="${escapeHtml(status)}" data-severity="${escapeHtml(severity)}">
      <td class="mono">${escapeHtml(id || "ID unavailable")}</td>
      <td>${severityBadge(severity)}</td>
      <td><strong>${escapeHtml(incident.title || "Untitled incident")}</strong><span class="workspace-cell-subtext">${escapeHtml(incident.description || incident.source_ip || "No details provided")}</span></td>
      <td><span class="workspace-status">${escapeHtml(status)}</span></td>
      <td>${escapeHtml(incident.assigned_to || incident.assignee || "Unassigned")}</td>
      <td>${escapeHtml(incident.mitre_technique || "—")}</td>
      <td><button class="btn btn-secondary workspace-row-action" type="button" data-open-incident="${escapeHtml(id)}" ${id ? "" : "disabled"}>Investigate</button></td>
    </tr>`;
  }).join("");
  return `
    ${workspaceNotice("Record identity", "Each incident is rendered by its incident ID. Identical titles or descriptions are retained as distinct records.", "info")}
    ${workspaceCard("Incident queue", `${incidents.length.toLocaleString()} records returned (maximum 200)`, `
      <div class="workspace-table-tools">
        <label class="workspace-select">Status<select data-incident-filter="status"><option value="ALL">All statuses</option><option value="ACTIVE">Active</option><option value="RESOLVED">Resolved</option><option value="FALSE_POSITIVE">False positive</option></select></label>
        <label class="workspace-select">Severity<select data-incident-filter="severity"><option value="ALL">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
        <span class="workspace-record-count" data-incident-count>${incidents.length.toLocaleString()} loaded</span>
      </div>
      <div class="workspace-table-wrap"><table class="workspace-table">
        <thead><tr><th>Incident ID</th><th>Severity</th><th>Incident</th><th>Status</th><th>Assigned</th><th>MITRE</th><th>Action</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="workspace-empty">No incidents were returned for this organization.</td></tr>'}</tbody>
      </table></div>
    `)}
  `;
}

function filterIncidentTable() {
  const root = document.getElementById("workspaceView");
  if (!root || activeWorkspace !== "incidents") return;
  const statusFilter = root.querySelector('[data-incident-filter="status"]')?.value || "ALL";
  const severityFilter = root.querySelector('[data-incident-filter="severity"]')?.value || "ALL";
  let visible = 0;
  root.querySelectorAll("[data-incident-row]").forEach(row => {
    const activeMatch = statusFilter !== "ACTIVE" ||
      !["RESOLVED", "FALSE_POSITIVE"].includes(row.dataset.status);
    const statusMatch = statusFilter === "ALL" || statusFilter === "ACTIVE" ||
      row.dataset.status === statusFilter;
    const matches = activeMatch && statusMatch &&
      (severityFilter === "ALL" || row.dataset.severity === severityFilter);
    row.hidden = !matches;
    row.style.display = matches ? "" : "none";
    if (matches) visible += 1;
  });
  const count = root.querySelector("[data-incident-count]");
  if (count) count.textContent = `${visible.toLocaleString()} shown`;
}

async function renderReportWorkspace() {
  const results = await Promise.allSettled([
    fetchJSON("/api/v1/metrics"),
    loadIncidents(200),
    loadEvents(500)
  ]);
  reportSnapshot = {
    metrics: results[0].status === "fulfilled" ? results[0].value : null,
    incidents: results[1].status === "fulfilled" ? (results[1].value.incidents || []) : [],
    events: results[2].status === "fulfilled" ? (results[2].value.events || []) : [],
    errors: results.map(result => result.status === "rejected" ? result.reason : null)
  };
  return `
    ${workspaceNotice("Report scope", "Data is loaded from authenticated organization-scoped metrics, incidents, and event endpoints. History is limited to the latest 200 incidents and 500 events; no report-history or PDF-generation API is connected.", "info")}
    ${reportSnapshot.errors.some(Boolean) ? workspaceNotice("Partial report data", "Some report sources did not load. The export includes only the sources that loaded successfully.", "warning") : ""}
    ${workspaceCard("Security posture summary", "Backend metrics from the current organization context", `
      <div class="workspace-report-range"><label for="reportRangeSelect">Time range</label><select id="reportRangeSelect" data-report-range><option value="1">Last 24 hours</option><option value="7" selected>Last 7 days</option><option value="30">Last 30 days</option><option value="all">All loaded records</option></select></div>
      <div class="workspace-metrics" id="reportMetrics"></div>
      <div class="workspace-report-counts" id="reportRecordCounts"></div>
      <button class="btn btn-primary" type="button" onclick="downloadScopedReport()">Export current range (CSV)</button>
    `)}
    ${workspaceCard("Report history", "Generated report archive", '<p class="workspace-empty">A report-history API is not available in the current backend.</p>')}
  `;
}

function getReportRangeValue() {
  const select = document.querySelector("[data-report-range]");
  return select ? select.value : "7";
}

function reportRowsWithinRange(records, range) {
  if (range === "all") return records;
  const days = Number(range) || 7;
  const now = Date.now();
  const cutoff = now - days * 24 * 60 * 60 * 1000;
  return records.filter(record => {
    const timestamp = Date.parse(record.timestamp || record.updated_at || record.created_at || "");
    return Number.isFinite(timestamp) && timestamp >= cutoff && timestamp <= now;
  });
}

function updateReportRange() {
  if (!reportSnapshot) return;
  const range = getReportRangeValue();
  const events = reportRowsWithinRange(reportSnapshot.events, range);
  const incidents = reportRowsWithinRange(reportSnapshot.incidents, range);
  const metrics = document.getElementById("reportMetrics");
  const counts = document.getElementById("reportRecordCounts");
  if (metrics) {
    metrics.innerHTML = [
      metricCard("Total events", reportSnapshot.metrics && reportSnapshot.metrics.total_events, "Backend total; not range-limited"),
      metricCard("Active incidents", reportSnapshot.metrics && reportSnapshot.metrics.active_incidents, "Backend current total"),
      metricCard("Critical incidents", reportSnapshot.metrics && reportSnapshot.metrics.critical_incidents, "Backend current total"),
      metricCard("Blocked IPs", reportSnapshot.metrics && reportSnapshot.metrics.blocked_ips, "Backend dashboard metric")
    ].join("");
  }
  if (counts) counts.innerHTML = `<span>${events.length.toLocaleString()} events</span><span>${incidents.length.toLocaleString()} incidents</span><span>Filtered for selected range</span>`;
}

async function downloadScopedReport() {
  let snapshot = reportSnapshot;
  if (!snapshot) {
    const results = await Promise.allSettled([loadIncidents(200), loadEvents(500)]);
    snapshot = {
      incidents: results[0].status === "fulfilled" ? (results[0].value.incidents || []) : [],
      events: results[1].status === "fulfilled" ? (results[1].value.events || []) : []
    };
    if (results.every(result => result.status === "rejected")) {
      const error = "No organization-scoped report sources could be loaded.";
      console.error(`[AegisSOAR] ${error}`);
      const reportArea = document.getElementById("reportContentArea");
      if (reportArea) {
        reportArea.innerHTML = `<div class="workspace-error" role="status"><strong>Export unavailable</strong><p>${escapeHtml(error)}</p></div>`;
        reportArea.style.display = "block";
      } else {
        alert(error);
      }
      return;
    }
  }
  const range = getReportRangeValue();
  const events = reportRowsWithinRange(snapshot.events || [], range).map(event => ({
    record_type: "event",
    id: eventIdentifier(event),
    timestamp: eventValue(event, "timestamp", "created_at"),
    severity: eventSeverity(event),
    status: eventValue(event, "status"),
    title: eventValue(event, "service", "event_type", "type"),
    source_ip: eventValue(event, "source_ip", "src_ip"),
    destination_ip: eventValue(event, "destination_ip", "dest_ip", "target_ip"),
    mitre_technique: eventValue(event, "mitre_technique", "technique_id"),
    details: eventValue(event, "message", "description")
  }));
  const incidents = reportRowsWithinRange(snapshot.incidents || [], range).map(incident => ({
    record_type: "incident",
    id: eventValue(incident, "id"),
    timestamp: eventValue(incident, "updated_at", "created_at", "timestamp"),
    severity: eventValue(incident, "severity"),
    status: eventValue(incident, "status"),
    title: eventValue(incident, "title"),
    source_ip: eventValue(incident, "source_ip"),
    destination_ip: "",
    mitre_technique: eventValue(incident, "mitre_technique"),
    details: eventValue(incident, "description")
  }));
  const columns = ["record_type", "id", "timestamp", "severity", "status", "title", "source_ip", "destination_ip", "mitre_technique", "details"];
  const csvEscape = value => `"${String(value ?? "").replace(/"/g, '""')}"`;
  const csv = [columns.join(","), ...events.concat(incidents).map(row => columns.map(column => csvEscape(row[column])).join(","))].join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `aegis-security-report-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

async function renderSettingsWorkspace() {
  const result = await Promise.allSettled([fetchJSON("/api/v1/auth/me")]);
  if (result[0].status === "rejected") {
    return workspaceCard("Authenticated profile", "User and organization context", workspaceError("Profile", result[0].reason));
  }
  const profile = result[0].value;
  return `
    ${workspaceCard("User profile", "Returned by the authenticated profile endpoint", `
      <div class="workspace-metrics">
        ${metricCard("Name", profile.full_name || profile.username || "Unavailable")}
        ${metricCard("Email", profile.email || "Unavailable")}
        ${metricCard("Role", profile.role || "Unavailable")}
        ${metricCard("Organization ID", profile.organization_id || "Unavailable")}
      </div>
      ${workspaceNotice("Access management", "The current organization/member APIs do not expose a safe authenticated, tenant-scoped administration surface. Team, role, integration, and security settings are not shown as editable controls.", "warning")}
    `)}
  `;
}

window.initWorkspaceNavigation = initWorkspaceNavigation;
window.navigateWorkspace = navigateWorkspace;
window.downloadScopedReport = downloadScopedReport;
