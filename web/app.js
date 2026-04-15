const scanForm = document.getElementById("scan-form");
const scanStatus = document.getElementById("scan-status");
const scanOutput = document.getElementById("scan-output");
const watchForm = document.getElementById("watch-form");
const watchList = document.getElementById("watch-list");

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

scanForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
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

  scanStatus.textContent = "scanning " + body.username + "...";
  scanOutput.textContent = "";
  try {
    const r = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      scanStatus.textContent = "error: HTTP " + r.status;
      return;
    }
    const data = await r.json();
    const found = (data.platforms || []).filter((p) => p.exists).length;
    scanStatus.textContent = "done — " + found + " platforms matched";
    scanOutput.textContent = JSON.stringify(data, null, 2);
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

refreshWatchlist();
