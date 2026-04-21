# cyberm4fia-osint — Yapilacaklar

## Sprint 9: Canli Ilerleme + Interaktif Graph  ✅
- [x] WebSocket / SSE ile scan progress (her phase bitince web UI'a event)
- [x] D3.js veya Cytoscape ile interaktif entity graph (web UI'da tiklanabilir ag haritasi)
- [x] Graph uzerinde node detayi (profil, email, telefon, cuzdana tikla -> detay paneli)

## Sprint 10: Zamanlanmis Tarama + Bildirim  ✅
- [x] Scheduled scan — watchlist'teki kullanicilari cron/timer ile otomatik tara
- [x] Degisiklik algila (yeni platform, kaybolan profil) ve bildir
- [x] Telegram bildirim hook'u (scan bitti, yeni bulgu)
- [x] Webhook desteği (genel entegrasyon icin POST callback)

## Sprint 11: Docker + Playwright Genisleme  ✅
- [x] Dockerfile — Tor + Playwright + tum bagimliliklar tek image
- [x] docker-compose.yml (API + Tor + isteğe bağlı CLI profili)
- [x] Playwright'i JS-heavy platformlarda (Instagram, X, TikTok, Threads, LinkedIn) varsayilan yap
- [x] Playwright screenshot'lari scan sonucuna ekle (--screenshots)

## Sprint 12: Geolocation Heatmap  ✅
- [x] core/geo.py — SQLite-cached Nominatim geocoder + GeoPoint dataclass
- [x] --geocode CLI flag + _phase_geocode engine phase
- [x] GET /heatmap/{username} API (duplicate coord folding)
- [x] Leaflet + Leaflet.heat web panel, OSM tiles, markers with popups

## Sprint 13: Username Correlation Scoring  ✅
- [x] core/correlation.py — evidence-first scorer, probabilistic OR
  (email/phone/crypto/name/location/bio/alias/avatar signals)
- [x] GET /correlate?a=&b= API endpoint
- [x] --correlate user_a,user_b CLI flag
- [x] Web UI panel with verdict badge + signals table

## Sprint 14: Report Comparison UI  ✅
- [x] core/compare.py — deep payload diff (platforms, emails, breaches,
  phones, crypto, geo) + per-platform profile_data field changes
- [x] core/history.get_scan(id) — fetch a specific scan by id
- [x] GET /compare?a=&b=&a_scan=&b_scan= API endpoint
- [x] --compare user_a,user_b CLI flag
- [x] Web UI side-by-side diff panel with added/removed coloring

## Sprint 15: Social Graph Overlap  ✅
- [x] core/social_graph.py — Jaccard similarity + shared follower/following
  sets, probabilistic combined score
- [x] GitHub fetcher via public REST API (paginated, 404-safe, max_pages cap)
- [x] GET /social-graph?a=&b=&platform=github API endpoint
- [x] --social-graph user_a,user_b CLI flag
- [x] Web UI panel listing shared connections with clickable GitHub links

## Sprint 16: Investigation Case Management  ✅
- [x] core/cases.py — SQLite Case + CaseNote + CaseBookmark CRUD
  (cascade delete via FK, status open/closed/archived)
- [x] /cases, /cases/{id}, /cases/{id}/notes, /cases/{id}/bookmarks REST API
- [x] --case-new/--case-list/--case-show/--case-note/--case-bookmark/--case-close CLI
- [x] Web UI panel: case list + detail with inline note/bookmark forms

## Sprint 17: Multi-user JWT Auth  ✅
- [x] core/auth.py — zero-dep PBKDF2-SHA256 user store + HS256 JWT
  (issue/decode, timing-safe compare, decoy-hash on unknown user)
- [x] Opt-in middleware gate (OSINT_AUTH_REQUIRED env var);
  OSINT_AUTH_SECRET for signing key
- [x] POST /auth/login (returns bearer token) + GET /auth/me
- [x] --create-user USER:PASS[:ROLE] CLI (roles: admin/analyst/viewer)

## Sprint 18: CSV/Excel Export  ✅
- [x] core/reporter/csv_export.py — ZIP bundle of per-section CSVs
  (summary/platforms/emails/phones/crypto/geo) + openpyxl XLSX multi-sheet
- [x] --output *.csv / *.csv.zip / *.xlsx dispatch wired into _save_report

## Sprint 19: Proxy Pool Rotation  ✅
- [x] core/proxy_pool.py — thread-safe round-robin with dead-proxy pruning
  (max_consecutive_failures, all-dead resurrection, success resets counter)
- [x] HTTPClient per-request health feedback (record success/failure around
  get/get_json/get_bytes)
- [x] --proxy-pool "p1,p2,..." and --proxy-file PATH CLI flags
  (dedup + merge with --proxy fallback)
- [x] ScanConfig.proxies plumbed through engine

## Backlog (oncelik sirasiyla)
- [ ] Mobile-responsive web UI
