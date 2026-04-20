const scanForm = document.getElementById("scan-form");
const scanStatus = document.getElementById("scan-status");
const scanOutput = document.getElementById("scan-output");
const scanLog = document.getElementById("scan-log");
const scanProgress = document.getElementById("scan-progress");
const scanProgressBar = document.getElementById("scan-progress-bar");
const watchForm = document.getElementById("watch-form");
const watchList = document.getElementById("watch-list");
const graphForm = document.getElementById("graph-form");
const graphStatus = document.getElementById("graph-status");
const nodeDetail = document.getElementById("node-detail");
const heatmapForm = document.getElementById("heatmap-form");
const heatmapStatus = document.getElementById("heatmap-status");

let cy = null;
let leafletMap = null;
let heatLayer = null;
let markerLayer = null;

const KIND_COLOR = {
  identity: "#ff4c60",
  platform: "#5fa8ff",
  email: "#ffd57a",
  breach: "#ff7a7a",
  phone: "#9ad0a5",
  crypto: "#c792ea",
  alias: "#e6edf3",
};

function buildFormBody() {
  const fd = new FormData(scanForm);
  const body = {
    username: fd.get("username"),
    email: fd.get("email") === "on",
    breach: fd.get("breach") === "on",
    web: fd.get("web") === "on",
    whois: fd.get("whois") === "on",
    dns: fd.get("dns") === "on",
    subdomain: fd.get("subdomain") === "on",
    photo: fd.get("photo") === "on",
    recursive: fd.get("recursive") === "on",
    passive: fd.get("passive") === "on",
    reverse_image: fd.get("reverse_image") === "on",
    past_usernames: fd.get("past_usernames") === "on",
    tor: fd.get("tor") === "on",
  };
  const cats = (fd.get("categories") || "").toString().trim();
  if (cats) body.categories = cats.split(",").map((s) => s.trim()).filter(Boolean);
  return body;
}

async function refreshWatchlist() {
  try {
    const r = await fetch("/watchlist");
    if (!r.ok) return;
    const data = await r.json();
    watchList.innerHTML = "";
    for (const e of data.entries) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      const tags = e.tags && e.tags.length ? " [" + e.tags.join(",") + "]" : "";
      label.textContent = "#" + e.id + "  " + e.username + tags;
      const btn = document.createElement("button");
      btn.className = "remove";
      btn.textContent = "remove";
      btn.onclick = async () => {
        await fetch("/watchlist/" + encodeURIComponent(e.username), { method: "DELETE" });
        refreshWatchlist();
      };
      li.appendChild(label);
      li.appendChild(btn);
      watchList.appendChild(li);
    }
  } catch (err) {
    console.error("watchlist fetch failed", err);
  }
}

function logLine(event) {
  const li = document.createElement("li");
  li.className = "kind-" + event.kind;
  const phase = event.phase ? "[" + event.phase + "] " : "";
  li.textContent = phase + event.kind + (event.message ? " — " + event.message : "");
  scanLog.appendChild(li);
  scanLog.scrollTop = scanLog.scrollHeight;
}

async function streamScan(body) {
  scanLog.innerHTML = "";
  scanProgress.classList.add("active");
  scanProgressBar.style.width = "2%";

  const r = await fetch("/scan/stream", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok || !r.body) throw new Error("HTTP " + r.status);

  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let totalPhases = 15; // approximate, engine has ~15 phases
  let doneCount = 0;
  let finalPayload = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const parts = buf.split("\n\n");
    buf = parts.pop() || "";
    for (const chunk of parts) {
      const line = chunk.trim();
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(5).trim();
      if (!payload) continue;
      let event;
      try { event = JSON.parse(payload); } catch { continue; }
      logLine(event);
      if (event.kind === "phase_end") {
        doneCount += 1;
        scanProgressBar.style.width = Math.min(95, (doneCount / totalPhases) * 100) + "%";
      }
      if (event.kind === "result") {
        finalPayload = event.data && event.data.payload;
      }
    }
  }
  scanProgressBar.style.width = "100%";
  setTimeout(() => scanProgress.classList.remove("active"), 500);
  return finalPayload;
}

scanForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = buildFormBody();
  const stream = scanForm.querySelector("[name='stream']").checked;
  scanStatus.textContent = "scanning " + body.username + "...";
  scanOutput.textContent = "";

  try {
    let data;
    if (stream) {
      data = await streamScan(body);
    } else {
      const r = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) { scanStatus.textContent = "error: HTTP " + r.status; return; }
      data = await r.json();
    }
    if (!data) { scanStatus.textContent = "no result"; return; }
    const found = (data.platforms || []).filter((p) => p.exists).length;
    scanStatus.textContent = "done — " + found + " platforms matched";
    scanOutput.textContent = JSON.stringify(data, null, 2);
    // Auto-load graph for this username.
    loadGraph(body.username);
  } catch (err) {
    scanStatus.textContent = "network error: " + err.message;
  }
});

watchForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(watchForm);
  const username = (fd.get("username") || "").toString().trim();
  if (!username) return;
  const tagsRaw = (fd.get("tags") || "").toString().trim();
  const tags = tagsRaw ? tagsRaw.split(",").map((s) => s.trim()).filter(Boolean) : [];
  await fetch("/watchlist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, tags, notes: "" }),
  });
  watchForm.reset();
  refreshWatchlist();
});

function renderGraph(payload) {
  if (!window.cytoscape) {
    graphStatus.textContent = "cytoscape not loaded";
    return;
  }
  const elements = [...payload.nodes, ...payload.edges];
  if (cy) cy.destroy();
  cy = window.cytoscape({
    container: document.getElementById("cy"),
    elements,
    layout: { name: "cose", animate: false, padding: 30 },
    style: [
      {
        selector: "node",
        style: {
          "label": "data(label)",
          "background-color": (ele) => KIND_COLOR[ele.data("kind")] || "#7d8590",
          "color": "#e6edf3",
          "font-size": 10,
          "font-family": "JetBrains Mono, ui-monospace, monospace",
          "text-valign": "bottom",
          "text-margin-y": 4,
          "width": 18,
          "height": 18,
          "border-width": 1,
          "border-color": "#0b0d10",
        },
      },
      {
        selector: 'node[kind = "identity"]',
        style: { "width": 30, "height": 30, "font-size": 12 },
      },
      {
        selector: "edge",
        style: {
          "line-color": "#262c33",
          "target-arrow-color": "#262c33",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "width": 1,
        },
      },
    ],
  });
  cy.on("tap", "node", (evt) => {
    nodeDetail.textContent = JSON.stringify(evt.target.data(), null, 2);
  });
}

async function loadGraph(username) {
  graphStatus.textContent = "loading graph for " + username + "...";
  nodeDetail.textContent = "";
  try {
    const r = await fetch("/graph/" + encodeURIComponent(username));
    if (r.status === 404) {
      graphStatus.textContent = "no scans yet for " + username;
      return;
    }
    if (!r.ok) {
      graphStatus.textContent = "error: HTTP " + r.status;
      return;
    }
    const data = await r.json();
    graphStatus.textContent = data.nodes.length + " nodes · " + data.edges.length + " edges";
    renderGraph(data);
  } catch (err) {
    graphStatus.textContent = "network error: " + err.message;
  }
}

graphForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fd = new FormData(graphForm);
  const username = (fd.get("username") || "").toString().trim();
  if (username) loadGraph(username);
});

function ensureMap() {
  if (leafletMap) return leafletMap;
  if (!window.L) return null;
  leafletMap = window.L.map("map", { worldCopyJump: true }).setView([20, 0], 2);
  window.L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "© OpenStreetMap",
    maxZoom: 18,
  }).addTo(leafletMap);
  return leafletMap;
}

async function loadHeatmap(username) {
  const map = ensureMap();
  if (!map) {
    heatmapStatus.textContent = "leaflet not loaded";
    return;
  }
  heatmapStatus.textContent = "loading heatmap for " + username + "...";
  if (heatLayer) { map.removeLayer(heatLayer); heatLayer = null; }
  if (markerLayer) { map.removeLayer(markerLayer); markerLayer = null; }

  try {
    const r = await fetch("/heatmap/" + encodeURIComponent(username));
    if (r.status === 404) { heatmapStatus.textContent = "no scans yet for " + username; return; }
    if (!r.ok) { heatmapStatus.textContent = "error: HTTP " + r.status; return; }
    const data = await r.json();
    const points = data.points || [];
    const markers = data.markers || [];
    if (!points.length) {
      heatmapStatus.textContent = "no geocoded locations (run with --geocode)";
      return;
    }
    heatLayer = window.L.heatLayer(points, { radius: 28, blur: 22, maxZoom: 12 }).addTo(map);
    markerLayer = window.L.layerGroup(
      markers.map((m) => window.L.marker([m.lat, m.lng]).bindPopup(
        "<b>" + (m.label || "") + "</b><br/>source: " + (m.source || "?")
      ))
    ).addTo(map);
    const bounds = window.L.latLngBounds(markers.map((m) => [m.lat, m.lng]));
    if (bounds.isValid()) map.fitBounds(bounds.pad(0.2));
    heatmapStatus.textContent = points.length + " unique locations · " + markers.length + " hits";
  } catch (err) {
    heatmapStatus.textContent = "network error: " + err.message;
  }
}

heatmapForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fd = new FormData(heatmapForm);
  const username = (fd.get("username") || "").toString().trim();
  if (username) loadHeatmap(username);
});

refreshWatchlist();
