let map;
let markersLayer;
const baseLayers = {};
const activeAttackers = new Map();
let activeThreatFilter = "ALL";
let mapResizeObserver;

const SEVERITY_COLORS = {
  CRITICAL: "#ff465b",
  HIGH: "#ff9a3c",
  MEDIUM: "#f5ca52",
  LOW: "#22c98b",
  UNKNOWN: "#35c8ff"
};

function initThreatMap() {
  const mapElement = document.getElementById("threatMap");
  if (!mapElement) return;
  if (!window.L) {
    mapElement.innerHTML = '<div class="map-error">Interactive map library is unavailable.</div>';
    console.error("[AegisSOAR] Leaflet failed to load; threat map cannot be initialized.");
    return;
  }

  if (map) map.remove();
  if (mapResizeObserver) mapResizeObserver.disconnect();
  activeAttackers.clear();
  activeThreatFilter = "ALL";

  const darkBase = L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
    {
      maxZoom: 16,
      minZoom: 1,
      keepBuffer: 3,
      updateWhenZooming: false,
      updateWhenIdle: true,
      attribution: '&copy; Esri, HERE, Garmin, <a href="https://www.openstreetmap.org/copyright">(c) OpenStreetMap contributors</a>, and the GIS user community'
    }
  );
  const darkReference = L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
    { maxZoom: 16, minZoom: 1 }
  );
  const cyberDark = L.layerGroup([darkBase, darkReference]);
  const lightBase = L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}",
    {
      maxZoom: 16,
      minZoom: 1,
      attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ'
    }
  );
  const lightReference = L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
    { maxZoom: 16, minZoom: 1 }
  );
  const lightMap = L.layerGroup([lightBase, lightReference]);
  const streetMap = L.tileLayer(
    "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
    {
      maxZoom: 19,
      minZoom: 1,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }
  );

  map = L.map(mapElement, {
    zoomControl: true,
    attributionControl: true,
    minZoom: 1.5,
    maxZoom: 8,
    layers: [cyberDark]
  }).setView([18, 0], 2);

  baseLayers["Cyber Dark"] = cyberDark;
  baseLayers["Light Canvas"] = lightMap;
  baseLayers["Street"] = streetMap;
  L.control.layers(baseLayers, null, { position: "topright", collapsed: true }).addTo(map);
  markersLayer = L.layerGroup().addTo(map);
  updateThreatMapCount();

  window.requestAnimationFrame(() => map && map.invalidateSize());
  if ("ResizeObserver" in window) {
    mapResizeObserver = new ResizeObserver(() => map && map.invalidateSize());
    mapResizeObserver.observe(mapElement);
  }
}

function makeThreatPopup({ ip, country, city, isp, score, title, severity }) {
  const popup = document.createElement("div");
  popup.className = "threat-popup";
  const heading = document.createElement("strong");
  heading.className = "threat-popup-title";
  heading.style.color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
  heading.textContent = title || "Security incident";
  popup.appendChild(heading);

  const rows = [
    ["Severity", severity],
    ["Source IP", ip],
    ["Location", [city, country].filter(Boolean).join(", ")],
    ["Network", isp],
    ["Threat score", score !== null && score !== undefined && score !== "" && Number.isFinite(Number(score)) ? `${Number(score)}/100` : null]
  ];
  rows.forEach(([label, value]) => {
    if (!value) return;
    const row = document.createElement("div");
    const key = document.createElement("span");
    key.textContent = `${label}: `;
    const content = document.createElement("span");
    content.textContent = String(value);
    row.append(key, content);
    popup.appendChild(row);
  });
  return popup;
}

function plotAttackerOnMap(ip, lat, lon, country, city, isp, score, incidentTitle, severity, incidentId, intelSource) {
  if (!map || !markersLayer) return false;
  if (intelSource !== "AbuseIPDB Live API") return false;
  if (lat === null || lat === undefined || lat === "" || lon === null || lon === undefined || lon === "") return false;
  if (!country || ["unknown", "unknown location"].includes(String(country).trim().toLowerCase())) return false;
  if (city && String(city).trim().toLowerCase() === "unknown") return false;

  const latitude = Number(lat);
  const longitude = Number(lon);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude) ||
      (latitude === 0 && longitude === 0) ||
      latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
    return false;
  }

  const normalizedSeverity = String(severity || "UNKNOWN").toUpperCase();
  const color = SEVERITY_COLORS[normalizedSeverity] || SEVERITY_COLORS.UNKNOWN;
  const key = incidentId ? `incident:${incidentId}` : `source:${ip || "unknown"}:${latitude}:${longitude}`;
  const previous = activeAttackers.get(key);
  if (previous) markersLayer.removeLayer(previous.marker);

  const marker = L.circleMarker([latitude, longitude], {
    radius: 6,
    color,
    weight: 2,
    opacity: 0.96,
    fillColor: color,
    fillOpacity: 0.3,
    className: `threat-marker-${SEVERITY_COLORS[normalizedSeverity] ? normalizedSeverity.toLowerCase() : "unknown"}`,
    bubblingMouseEvents: false
  });
  marker.bindPopup(makeThreatPopup({
    ip,
    country,
    city,
    isp,
    score,
    title: incidentTitle,
    severity: normalizedSeverity
  }));
  activeAttackers.set(key, { marker, severity: normalizedSeverity });
  applyThreatMapFilter();
  return true;
}

function applyThreatMapFilter() {
  if (!markersLayer) return;
  markersLayer.clearLayers();
  activeAttackers.forEach(({ marker, severity }) => {
    if (activeThreatFilter === "ALL" || activeThreatFilter === severity) {
      markersLayer.addLayer(marker);
    }
  });
  updateThreatMapCount();
}

function filterThreatMap(severity) {
  activeThreatFilter = String(severity || "ALL").toUpperCase();
  applyThreatMapFilter();
}

function fitThreatMapToMarkers() {
  if (!map || !activeAttackers.size) return;
  const markers = Array.from(activeAttackers.values(), ({ marker }) => marker);
  if (markers.length === 1) {
    map.setView(markers[0].getLatLng(), Math.min(3, map.getMaxZoom()), { animate: false });
    return;
  }
  const bounds = L.featureGroup(markers).getBounds();
  if (bounds.isValid()) {
    map.fitBounds(bounds, { padding: [36, 36], maxZoom: 3, animate: false });
  }
}

function removeThreatFromMap(incidentId) {
  if (!incidentId) return;
  activeAttackers.delete(`incident:${incidentId}`);
  applyThreatMapFilter();
}

function updateThreatMapCount() {
  const count = document.getElementById("mapMarkerCount");
  if (!count) return;
  const visibleCount = Array.from(activeAttackers.values()).filter(({ severity }) =>
    activeThreatFilter === "ALL" || activeThreatFilter === severity
  ).length;
  count.innerText = `${visibleCount} mapped`;
}

window.initThreatMap = initThreatMap;
window.plotAttackerOnMap = plotAttackerOnMap;
window.filterThreatMap = filterThreatMap;
window.fitThreatMapToMarkers = fitThreatMapToMarkers;
window.removeThreatFromMap = removeThreatFromMap;
window.resizeThreatMap = () => window.requestAnimationFrame(() => map && map.invalidateSize({ pan: false }));
