let map;
let markersLayer;
const activeAttackers = new Map();

function initThreatMap() {
  const mapElement = document.getElementById("threatMap");
  if (!mapElement) return;

  map = L.map("threatMap", {
    zoomControl: true,
    attributionControl: false,
    minZoom: 1.5,
    maxZoom: 8
  }).setView([20, 0], 2);

  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    subdomains: "abcd",
    maxZoom: 19
  }).addTo(map);

  markersLayer = L.layerGroup().addTo(map);
}

function plotAttackerOnMap(ip, lat, lon, country, city, isp, score, incidentTitle) {
  if (!map || !lat || !lon || (lat === 0 && lon === 0)) return;

  const color = score >= 85 ? "#ef4444" : (score >= 60 ? "#f59e0b" : "#06b6d4");

  const customIcon = L.divIcon({
    className: "radar-marker-icon",
    html: `
      <div style="
        position: relative;
        width: 18px;
        height: 18px;
      ">
        <div style="
          position: absolute;
          width: 100%;
          height: 100%;
          border-radius: 50%;
          background: ${color};
          box-shadow: 0 0 12px ${color};
        "></div>
        <div style="
          position: absolute;
          width: 100%;
          height: 100%;
          border-radius: 50%;
          border: 2px solid ${color};
          animation: pulse-ring 1.8s infinite;
        "></div>
      </div>
    `,
    iconSize: [18, 18],
    iconAnchor: [9, 9]
  });

  const marker = L.marker([lat, lon], { icon: customIcon });

  const popupContent = `
    <div style="color: #0f172a; font-family: sans-serif; font-size: 12px; line-height: 1.5;">
      <div style="font-weight: bold; font-size: 13px; color: ${color}; margin-bottom: 4px;">
        ⚠️ Threat Detected: ${incidentTitle || 'Hostile Connection'}
      </div>
      <div><strong>IP:</strong> <code>${ip}</code></div>
      <div><strong>Location:</strong> ${city}, ${country}</div>
      <div><strong>Network:</strong> ${isp}</div>
      <div><strong>Threat Score:</strong> <span style="font-weight: bold; color: ${color};">${score}/100</span></div>
    </div>
  `;

  marker.bindPopup(popupContent);
  markersLayer.addLayer(marker);

  map.panTo([lat, lon], { animate: true, duration: 0.8 });
  marker.openPopup();
}

window.initThreatMap = initThreatMap;
window.plotAttackerOnMap = plotAttackerOnMap;
